//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-31.
//

import Foundation
@testable import K1

import ASN1Decoder

extension PublicKey {
    enum WycheproofDERDecodeError: Swift.Error {
        case expectedFirstElementToBeSequence
        case expectedTopLevelObjectToHaveSeqeuenceTag
        case expectedTopLevelSequenceWithElementCount(of: Int, butGot: Int)
        case elementLacksIdentifier(elementIndex: Int)
        case expectedBitString(atIndex: Int)
        case failedToCastBitstringToData
    }
    
    private static func importPublicKeyDataFromASN1Object(der: Data) throws -> Data {
        
        let asn1Objects = try ASN1DERDecoder.decode(data: der)
        
        guard asn1Objects.count == 1 else {
            throw WycheproofDERDecodeError.expectedTopLevelSequenceWithElementCount(of: 1, butGot: asn1Objects.count)
        }
        
        guard
            let topLevelObjectIdentifier = asn1Objects[0].identifier,
            case let topLevelObjectTag = topLevelObjectIdentifier.tagNumber(),
            topLevelObjectTag == .sequence else {
            throw WycheproofDERDecodeError.expectedTopLevelObjectToHaveSeqeuenceTag
        }
        
        
        let bitstringObjectElementIndex = 1
        let expectedElementCount = bitstringObjectElementIndex + 1
        
        guard asn1Objects[0].subCount() == expectedElementCount else {
            throw WycheproofDERDecodeError.expectedTopLevelSequenceWithElementCount(of: expectedElementCount, butGot: asn1Objects.count)
        }
        
        guard let bitstringObject = asn1Objects[0].sub(bitstringObjectElementIndex) else {
            throw WycheproofDERDecodeError.expectedBitString(atIndex: bitstringObjectElementIndex)
        }
        
        guard let bitstringObjectIdentifier = bitstringObject.identifier else {
            throw WycheproofDERDecodeError.elementLacksIdentifier(elementIndex: bitstringObjectElementIndex)
        }
        
        guard
            case let bitstringObjectTag = bitstringObjectIdentifier.tagNumber(),
            bitstringObjectTag == .bitString
        else {
            throw WycheproofDERDecodeError.expectedBitString(atIndex: bitstringObjectElementIndex)
        }
        
        guard let bitstringData = bitstringObject.value as? Data else {
            throw WycheproofDERDecodeError.failedToCastBitstringToData
        }
        
        return bitstringData

    }
    

    static func `import`(der: Data) throws -> Self {
        let publicKeyData = try importPublicKeyDataFromASN1Object(der: der)
        return try Self.import(from: publicKeyData)
    }
}
