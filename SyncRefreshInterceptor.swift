//
//  SyncRefreshInterceptor.swift
//
//
//  Created by Jacob Chan on 7/27/21.
//

import Foundation
import Alamofire

// MARK: Locks and sync variable

private let requestLock = NSLock()
private let isRefreshingLock = NSLock()

private var isRefreshing = false

// **Atomically** check if there's a refresh request in flight, if no, update
// `isRefreshing` to true and return true, otherwise return false
// Essentially we are using a lock/mutex to implement compare-and-swap
private func atomicCheckAndSetRefreshing() -> Bool {
    isRefreshingLock.lock(); defer { isRefreshingLock.unlock() }

    if !isRefreshing {
        isRefreshing = true

        return true
    }

    return false
}

private func atomicSetRefreshing(newVal: Bool) {
    isRefreshingLock.lock(); defer { isRefreshingLock.unlock() }

    isRefreshing = newVal
}

class SyncRefreshInterceptor: RequestInterceptor {
    private var accessToken: String {
        return storage.getAccessToken()
    }

    private var refreshToken: String {
        return storage.getRefreshToken()
    }

    private let storage: AppStorage

    public init(storage: AppStorage) {
        self.storage = storage
    }

    func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        if (urlRequest.url?.absoluteString) != nil {
            var urlRequest = urlRequest

            if !accessToken.isEmpty {
                print(accessToken)

                urlRequest.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            }
            urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")

            return completion(.success(urlRequest))
        }

        return completion(.success(urlRequest))
    }

    func retry(_ request: Request, for session: Session, dueTo error: Error, completion: @escaping (RetryResult) -> Void) {
        if let response = request.task?.response as? HTTPURLResponse,
           response.statusCode == 401 {

            if atomicCheckAndSetRefreshing() {
                // The conditional expression `atomicCheckAndSetRefreshing()`
                // atomically returns a *true* when `isRefreshing` *was* a
                // false, when that happens we know the current running thread
                // has an exclusive hold over the right to send out the refresh
                // token request.

                // Perform token refresh and blocking wait for the result to come back
                let refreshSuccessful = syncRefreshToken()
                if refreshSuccessful {
                    completion(.retry)
                } else {
                    // Bubble up the original API request error (401) to the
                    // its completion closure
                    completion(.doNotRetryWithError(error))
                }
            } else {
                // The conditional fails, at this point we know `isRefreshing`
                // is false, and there's must be a refresh request in flight.
                // We don't need to send out another refresh request.
                //
                // Here we re-queue or *retry* the original request with a delay
                // hoping that by the time the delay ends, a new access token
                // will become available.
                //
                // We need to retry the original request with a delay for a
                // reasonable amount of time, the delay should be *short* enough
                // that it doesn't degrade performance, but also long enough
                // that a refresh request should hopefully come back with a
                // result before it ends.
                //
                // IMPORTANT: The latter is **important**, because it's possible that
                // the delay is too short, the API request with the
                // not-yet-updated-access-token might be retried prematurely before the
                // previous refresh request comes back, resulting in another redundant
                // refresh request (should be harmless though).
                //
                // This delay and synchronised refresh request call give us the
                // **debouncing** behaviour whereby only one refresh request
                // gets triggered regardless how many API requests with 401
                // happen beforehand.

                completion(.retryWithDelay(2))
            }
        } else {
            completion(.doNotRetryWithError(error))
        }
    }

    private func syncRefreshToken() -> Bool {
        // Perform a synchronised and synchronous token refresh request.
        //
        // It needs to be both **synchronised** (i.e. no other threads can send
        // it while it's in flight), and **synchronous** (i.e. the interceptor
        // chain can not proceed without it comes back with a result)

        requestLock.lock()
        defer {
            atomicSetRefreshing(newVal: false)

            requestLock.unlock()
        }

        if let request = try? SetupRequestInfo.refresh(token: refreshToken, bearer: accessToken).asURLRequest() {
            let data = URLSession.shared.synchronousDataTask(with: request)
            if let data = data {
                let refreshResp = try? JSONDecoder().decode(BaseResponse<LoginResponse>.self, from: data)
                if let tokens = refreshResp?.data,
                   let refresh = tokens.refreshToken,
                   let access = tokens.accessToken {
                    self.storage.setTokens(accessToken: access, refreshToken: refresh)

                    return true
                }
            }
        }

        return false
    }
}

extension URLSession {
    func synchronousDataTask(with request: URLRequest) -> Data? {
        var data: Data?

        let semaphore = DispatchSemaphore(value: 0)

        let dataTask = self.dataTask(with: request) { (result, _, _) in
            // IMPORTANT: This closure must be executed in a thread that's
            // different from the calling thread, otherwise it will deadlock,
            // because at this point the calling thread is waiting for the
            // semaphore to be signaled.
            //
            // If the `dataTask` for some reason tries to schedule the closure
            // to execute in the calling thread, it will wait forever. Because
            // the calling thread is also waiting for this closure to run,
            // hence a deadlock.
            //
            // So here we rely on an implicit assumption that `dataTask` will
            // always call the closure in a different thread...

            data = result

            _ = semaphore.signal()
        }

        dataTask.resume()

        // Wait for the dataTask to call the above closure to signal the
        // completion of the token refresh request.
        //
        // Have a timeout to avoid deadlocks when the aforementioned _implicit_
        // assumption (i.e. the closure will always run in a separate thread)
        // doesn't hold.
        _ = semaphore.wait(timeout: DispatchTime.now() + .seconds(6))

        return data
    }
}
