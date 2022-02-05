//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//


internal extension K1.PublicKey {
    
    @usableFromInline
    struct Wrapped: Equatable {
        
        internal let uncompressedRaw: [UInt8]
    
        internal init(
            uncompressedRaw: [UInt8]
        ) throws {
            guard uncompressedRaw.count == K1.Format.uncompressed.length else {
                // Only accept uncompressed public key here.
                throw K1.Error.incorrectByteCountOfPublicKey(got: uncompressedRaw.count, acceptableLengths: [K1.Format.uncompressed.length])
            }
            self.uncompressedRaw = uncompressedRaw
        }
    }
}

internal extension K1.PublicKey.Wrapped {
    
    @usableFromInline
    func rawRepresentation(format: K1.Format) throws -> [UInt8] {
        switch format {
        case .uncompressed: return uncompressedRaw
        case .compressed: return try Array(Bridge.compress(publicKey: self))
        }
    }
    
    static func `import`<D: ContiguousBytes>(
        from raw: D)
    throws -> Self {
        try .import(from: raw.bytes)
    }
    
    @usableFromInline
    static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.uncompressedRaw == rhs.uncompressedRaw
    }
}
