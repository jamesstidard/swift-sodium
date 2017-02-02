//
//  Hash.swift
//  Sodium
//
//  Created by James Stidard on 02/02/2017.
//  Copyright © 2017 Frank Denis. All rights reserved.
//

import Foundation


public class Hash {
    var sha256 = SHA256()
    var sha512 = SHA512()
    
    class SHA256 {
        public let Bytes = Int(crypto_hash_sha256_bytes())
        
        public func hash(message: Data) -> Data? {
            return hash(message: message, outputLength: Bytes)
        }
        
        public func hash(message: Data, outputLength: Int) -> Data? {
            var output = Data(count: outputLength)
            let result = output.withUnsafeMutableBytes { outputPtr in
                return message.withUnsafeBytes { messagePtr in
                    return crypto_hash_sha256(
                        outputPtr,
                        messagePtr,
                        CUnsignedLongLong(message.count))
                }
            }
            
            if result != 0 {
                return nil
            }
            
            return output
        }
        
        public func initStream() -> Stream? {
            return Stream(outputLength: Bytes)
        }
        
        public func initStream(outputLength: Int) -> Stream? {
            return Stream(outputLength: outputLength)
        }
        
        public class Stream {
            public var outputLength: Int = 0
            private var state: UnsafeMutablePointer<crypto_hash_sha256_state>?
            
            init?(outputLength: Int) {
                state = UnsafeMutablePointer<crypto_hash_sha256_state>.allocate(capacity: 1)
                guard let state = state else {
                    return nil
                }
                
                let result = crypto_hash_sha256_init(state)
                
                if result != 0 {
                    return nil
                }
                
                self.outputLength = outputLength;
            }
            
            deinit {
                state?.deallocate(capacity: 1)
            }
            
            public func update(input: Data) -> Bool {
                return input.withUnsafeBytes { inputPtr in
                    return crypto_hash_sha256_update(state!, inputPtr, CUnsignedLongLong(input.count)) == 0
                }
            }
            
            public func final() -> Data? {
                var output = Data(count: outputLength)
                let result = output.withUnsafeMutableBytes { outputPtr in
                    crypto_hash_sha256_final(state!, outputPtr)
                }
                
                if result != 0 {
                    return nil
                }
                
                return output
            }
        }
    }
    
    class SHA512 {
        public let Bytes = Int(crypto_hash_sha512_bytes())
        
        public func hash(message: Data) -> Data? {
            return hash(message: message, outputLength: Bytes)
        }
        
        public func hash(message: Data, outputLength: Int) -> Data? {
            var output = Data(count: outputLength)
            let result = output.withUnsafeMutableBytes { outputPtr in
                return message.withUnsafeBytes { messagePtr in
                    return crypto_hash_sha512(
                        outputPtr,
                        messagePtr,
                        CUnsignedLongLong(message.count))
                }
            }
            
            if result != 0 {
                return nil
            }
            
            return output
        }
        
        public func initStream() -> Stream? {
            return Stream(outputLength: Bytes)
        }
        
        public func initStream(outputLength: Int) -> Stream? {
            return Stream(outputLength: outputLength)
        }
        
        public class Stream {
            public var outputLength: Int = 0
            private var state: UnsafeMutablePointer<crypto_hash_sha512_state>?
            
            init?(outputLength: Int) {
                state = UnsafeMutablePointer<crypto_hash_sha512_state>.allocate(capacity: 1)
                guard let state = state else {
                    return nil
                }
                
                let result = crypto_hash_sha512_init(state)
                
                if result != 0 {
                    return nil
                }
                
                self.outputLength = outputLength;
            }
            
            deinit {
                state?.deallocate(capacity: 1)
            }
            
            public func update(input: Data) -> Bool {
                return input.withUnsafeBytes { inputPtr in
                    return crypto_hash_sha512_update(state!, inputPtr, CUnsignedLongLong(input.count)) == 0
                }
            }
            
            public func final() -> Data? {
                var output = Data(count: outputLength)
                let result = output.withUnsafeMutableBytes { outputPtr in
                    crypto_hash_sha512_final(state!, outputPtr)
                }
                
                if result != 0 {
                    return nil
                }
                
                return output
            }
        }
    }
}
