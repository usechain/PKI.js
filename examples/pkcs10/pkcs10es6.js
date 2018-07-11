/* Created by Zhouhh@usechain.net
* Date: 2018.7.6
* Copyright 2018-2020 All right reserved
*/
/* eslint-disable no-undef,no-unreachable */
import * as asn1js from "asn1js";
import { arrayBufferToString, stringToArrayBuffer, toBase64, fromBase64 } from "pvutils";
import { getCrypto, getAlgorithmParameters, setEngine } from "../../src/common.js";
import CertificationRequest from "../../src/CertificationRequest.js";
import AttributeTypeAndValue from "../../src/AttributeTypeAndValue.js";
import Attribute from "../../src/Attribute.js";
import Extension from "../../src/Extension.js";
import Extensions from "../../src/Extensions.js";
import RSAPublicKey from "../../src/RSAPublicKey.js";
import GeneralNames from "../../src/GeneralNames.js";
import GeneralName from "../../src/GeneralName.js";
import { getParametersValue, isEqualBuffer, clearProps } from "pvutils";

//<nodewebcryptoossl>
//*********************************************************************************
let pkcs10Buffer = new ArrayBuffer(0);

var Operations={sign:"sign", encrypt:"encrypt", generatekey:"generatekey", importkey:"importkey", exportkey:"exportkey", verify:"verify"}
var HashAlg={SHA1:"sha-1",SHA256:"sha-256",SHA384:"sha-384",SHA512:"sha-512"}
var SignAlg={RSA15:"RSASSA-PKCS1-V1_5",RSA2:"RSA-PSS",ECDSA:"ECDSA"}

let hashAlg = HashAlg.SHA256; //"SHA-1";
let signAlg = SignAlg.ECDSA; //"RSASSA-PKCS1-V1_5";

class KeyPair{
	constructor(privateKey,publicKey){
		this.privateKey=privateKey
		this.publicKey=publicKey

	}
}
class CSRConfig{
	constructor(parameters={}) {
		this.commonName=""
		this.countryName=getParametersValue(parameters, "countryName", CSRConfig.defaultValues("countryName"));
		this.hashAlg=getParametersValue(parameters,"hashAlg",CSRConfig.defaultValues("hashAlg"))
		this.signAlg=getParametersValue(parameters,"signAlg",CSRConfig.defaultValues("signAlg"))
		this.email=getParametersValue(parameters,"email",CSRConfig.defaultValues("email"))
		this.domain=getParametersValue(parameters,"domain",CSRConfig.defaultValues("domain"))
		this.anotherdomain=getParametersValue(parameters,"anotherdomain",CSRConfig.defaultValues("anotherdomain"))
		this.iPAddress=getParametersValue(parameters,"iPAddress",CSRConfig.defaultValues("iPAddress"))
		//this.organization
		//this.organizationalUnit
		this.stateOrProvinceName
        this.localityName
		this.streetAddress
        this.organizationalUnitName
        this.organizationName
	}

	static defaultValues(key){
		switch(key){
			case "countryName":
				return ""
			case "hashAlg":
				return HashAlg.SHA256;
			case "sigAlg":
				return SignAlg.RSA2;//ECDSA
			case "email":
				return "";
			case "domain":
				return "";
			case "anotherdomain":
				return "";
            case "iPAddress":
                return "";
            default:
                throw new Error(`Invalid member name for CSRConfig class: ${key}`);
		}


	}
}
//arrayBuffer to string
function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

//string to array buffer
function str2ab(str) {
    var buf = new ArrayBuffer(str.length); // 1 bytes for each char
    var bufView = new Uint8Array(buf);
    for (var i=0, strLen=str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

//*********************************************************************************
// genKeyHash: digest content
// @param content: content to be hash
// @param hashAlgrithm
// @return BufferArray(20)
function genKeyHash(content,hashAlgorithm = "SHA-1") {
    //region Get a "crypto" extension
    const crypto = getCrypto();
    if(typeof crypto === "undefined")
        throw new Error("Unable to create WebCrypto object");
    // //endregion

    let arr=str2ab(content)//content.split("")//
    //const arr = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    //const arr = new Uint8Array([0x31, 0x32, 0x33, 0x34]);
    //const arr = new Uint8Array([0x31]);
    //const arr = new Uint8Array([0x32, 0x31, 0x34, 0x33]);
	let  c = new Uint8Array(arr)

	return crypto.digest({ name: hashAlgorithm },c)
}

//*********************************************************************************
//region Auxiliary functions
//*********************************************************************************
function formatPEM(pemString)
{
	/// <summary>Format string in order to have each line with length equal to 63</summary>
	/// <param name="pemString" type="String">String to format</param>
	
	const stringLength = pemString.length;
	let resultString = "";
	
	for(let i = 0, count = 0; i < stringLength; i++, count++)
	{
		if(count > 63)
		{
			resultString = `${resultString}\r\n`;
			count = 0;
		}
		
		resultString = `${resultString}${pemString[i]}`;
	}
	
	return resultString;
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Create PKCS#10
//*********************************************************************************
function createPKCS10Internal(config={})
{
	if(!config) {
		throw new Error("config is empty")
	}

	if(config.hashAlg) {
		hashAlg=config.hashAlg;
	}
	if(config.signAlg) {
		signAlg=config.signAlg
	}

	//region Initial variables
	let sequence = Promise.resolve();
	
	const pkcs10 = new CertificationRequest();
	
	let publicKey;
	let privateKey;
	//endregion
	
	//region Get a "crypto" extension
	const crypto = getCrypto();
	if(typeof crypto === "undefined")
		return Promise.reject("No WebCrypto extension found");
	//endregion
	
	//region Put a static values

	pkcs10.version = 2;
	if(!config.commonName) throw new Error("common name must not be empty")
    pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
        type: "2.5.4.3",//commonName
        value: new asn1js.Utf8String({ value: config.commonName })
    }));

	if(config.organization) {
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.6.4",//organization
            value: new asn1js.PrintableString({value: config.organization})
        }));
    }
	if(config.organizationalUnit) {
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.6.5",//organizationalUnit
            value: new asn1js.PrintableString({value: config.organizationalUnit})
        }));
    }
    if(config.organizationName) {
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.10",//organization
            value: new asn1js.PrintableString({value: config.organizationName})
        }));
    }
    if(config.organizationalUnitName) {
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.11",//organizationalUnit
            value: new asn1js.PrintableString({value: config.organizationalUnitName})
        }));
    }

    if(config.countryName) {
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6",//countryName
            value: new asn1js.PrintableString({value: config.countryName})
        }));
    }

    if(config.stateOrProvinceName) {
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.8",//stateOrProvinceName
            value: new asn1js.PrintableString({value: config.stateOrProvinceName})
        }));
    }
    if(config.localityName) {
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.7",//stateOrProvinceName
            value: new asn1js.PrintableString({value: config.localityName})
        }));
    }
    if(config.streetAddress) {
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.9",//streetAddress
            value: new asn1js.PrintableString({value: config.streetAddress})
        }));
    }

	//General Names
	let gn={names: []}

	//email
	if(config.email) {
		gn.names.push(new GeneralName({
            type: 1, // rfc822Name
            value: config.email
        }))
	}

	//domain
    if(config.domain){
        gn.names.push( new GeneralName({
            type: 2, // dNSName
            value: config.domain
        }))
	}

	//another domain
	if(config.anotherdomain) {
        gn.names.push(new GeneralName({
            type: 2, // dNSName
            value: config.anotherdomain
        }))
    }

    //ipaddress
    if(config.iPAddress) {
        gn.names.push( new GeneralName({
            type: 7, // iPAddress
            value: new asn1js.OctetString({valueHex: (new Uint8Array(config.iPAddress.split("."))).buffer})
        }))
    }

    const altNames = new GeneralNames(gn);

    pkcs10.attributes = [];
	//endregion
	
	//region Create a new key pair
	sequence = sequence.then(() =>
	{
		if(!config.keyPair) {
            //region Get default algorithm parameters for key generation
            const algorithm = getAlgorithmParameters(signAlg, Operations.generatekey);
            if ("hash" in algorithm.algorithm)
                algorithm.algorithm.hash.name = config.hashAlg;
            //endregion

            return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
        }else{
			return config.keyPair;
		}

	});
	//endregion
	
	//region Store new key in an interim variables
	sequence = sequence.then(keyPair =>
	{
		publicKey = keyPair.publicKey;
		privateKey = keyPair.privateKey;
		//TODO： save keypair
	},
	error => Promise.reject((`Error during key generation: ${error}`))
	);
	//endregion
	
	//region Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
	sequence = sequence.then(() => pkcs10.subjectPublicKeyInfo.importKey(publicKey));
	//endregion
	
	//region SubjectKeyIdentifier
	sequence = sequence.then(() => crypto.digest({ name: "SHA-1" },
		pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex))
		.then(result =>
		{

			pkcs10.attributes.push(new Attribute({
				type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
				values: [(new Extensions({
					extensions: [
						new Extension({
							extnID: "2.5.29.14",//subjectKeyIdentifier
							critical: false,
							extnValue: (new asn1js.OctetString({ valueHex: result })).toBER(false)
						}),
						new Extension({
							extnID: "2.5.29.17",//subjectAltName
							critical: false,
							extnValue: altNames.toSchema().toBER(false)
						})
					]
				})).toSchema()]
			}));
		}
		);
	//endregion
	
	//region Signing final PKCS#10 request
	sequence = sequence.then(() => pkcs10.sign(privateKey, hashAlg),
		error => Promise.reject(`Error during exporting public key: ${error}`));
	//endregion
	
	return sequence.then(() =>
	{
		pkcs10Buffer = pkcs10.toSchema().toBER(false);
		
	}, error => Promise.reject(`Error signing PKCS#10: ${error}`));
}
//*********************************************************************************
//create pem format csr
//
// function createPKCS10(config){
// 	return createPKCS10BER(config)
// }

//@param format:BER or PEM
function createPKCS10(config,format="PEM"){

	if( format == "PEM") {
        createPKCS10PEM(config)
	}else {
        return createPKCS10BER(config)
    }
}

function createPKCS10PEM(config)
{
	return Promise.resolve().then(() => createPKCS10Internal(config)).then(() =>
	{
		let resultString = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
		resultString = `${resultString}${formatPEM(toBase64(arrayBufferToString(pkcs10Buffer)))}`;
		resultString = `${resultString}\r\n-----END CERTIFICATE REQUEST-----\r\n`;
		
		return resultString
	});
}

//*********************************************************************************
//create binary csr
function createPKCS10BER(config)
{
    return Promise.resolve().then(() => createPKCS10Internal(config)).then(() => pkcs10Buffer);
}

//*********************************************************************************
//endregion
//*********************************************************************************
//region Parse existing PKCS#10
//*********************************************************************************
function parsePKCS10(pem){
    return parsePKCS10PEM(pem);
}
function parsePKCS10PEM(pem)
{
	//region Initial activities

	let subject=""
	let exten=""

	//endregion
	
	//region Decode existing PKCS#10
	const stringPEM = pem.replace(/(-----(BEGIN|END) CERTIFICATE REQUEST-----|\n)/g, "");
	
	const asn1 = asn1js.fromBER(stringToArrayBuffer(fromBase64((stringPEM))));
	const pkcs10 = new CertificationRequest({ schema: asn1.result });
	//endregion
	
	//region Parse and display information about "subject"
	const typemap = {
		"2.5.4.6": "C",
		"2.5.4.11": "OU",
		"2.5.4.10": "O",
		"2.5.4.3": "CN",
		"2.5.4.7": "L",
		"2.5.4.8": "S",
		"2.5.4.12": "T",
		"2.5.4.42": "GN",
		"2.5.4.43": "I",
		"2.5.4.4": "SN",
		"1.2.840.113549.1.9.1": "E-mail"
	};
	
	for(let i = 0; i < pkcs10.subject.typesAndValues.length; i++)
	{
		let typeval = typemap[pkcs10.subject.typesAndValues[i].type];
		if(typeof typeval === "undefined")
			typeval = pkcs10.subject.typesAndValues[i].type;
		
		const subjval = pkcs10.subject.typesAndValues[i].value.valueBlock.value;
		const ulrow = `${typeval}  ${subjval}`;
		

		subject  = subject + ulrow;

		if(typeval === "CN")
		{
			// not using
			let cn = subjval;

		}
	}
	//endregion
	
	//region Put information about public key size
	let publicKeySize = "< unknown >";
	
	if(pkcs10.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== (-1))
	{
		const asn1PublicKey = asn1js.fromBER(pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
		const rsaPublicKeySimple = new RSAPublicKey({ schema: asn1PublicKey.result });
		const modulusView = new Uint8Array(rsaPublicKeySimple.modulus.valueBlock.valueHex);
		let modulusBitLength = 0;
		
		if(modulusView[0] === 0x00)
			modulusBitLength = (rsaPublicKeySimple.modulus.valueBlock.valueHex.byteLength - 1) * 8;
		else
			modulusBitLength = rsaPublicKeySimple.modulus.valueBlock.valueHex.byteLength * 8;
		
		publicKeySize = modulusBitLength.toString();
	}
	
    let keysize = publicKeySize;
	//endregion
	
	//region Put information about signature algorithm
	const algomap = {
		"1.2.840.113549.1.1.2": "MD2 with RSA",
		"1.2.840.113549.1.1.4": "MD5 with RSA",
		"1.2.840.10040.4.3": "SHA1 with DSA",
		"1.2.840.10045.4.1": "SHA1 with ECDSA",
		"1.2.840.10045.4.3.2": "SHA256 with ECDSA",
		"1.2.840.10045.4.3.3": "SHA384 with ECDSA",
		"1.2.840.10045.4.3.4": "SHA512 with ECDSA",
		"1.2.840.113549.1.1.10": "RSA-PSS",
		"1.2.840.113549.1.1.5": "SHA1 with RSA",
		"1.2.840.113549.1.1.14": "SHA224 with RSA",
		"1.2.840.113549.1.1.11": "SHA256 with RSA",
		"1.2.840.113549.1.1.12": "SHA384 with RSA",
		"1.2.840.113549.1.1.13": "SHA512 with RSA"
	};
	let signatureAlgorithm = algomap[pkcs10.signatureAlgorithm.algorithmId];
	if(typeof signatureAlgorithm === "undefined")
		signatureAlgorithm = pkcs10.signatureAlgorithm.algorithmId;
	else
		signatureAlgorithm = `${signatureAlgorithm} (${pkcs10.signatureAlgorithm.algorithmId})`;
	
	let sigalgo = signatureAlgorithm;
	//endregion
	
	//region Put information about PKCS#10 attributes
	if("attributes" in pkcs10)
	{
		for(let i = 0; i < pkcs10.attributes.length; i++)
		{
			const typeval = pkcs10.attributes[i].type;
			let subjval = "";
			
			for(let j = 0; j < pkcs10.attributes[i].values.length; j++)
			{
				// noinspection OverlyComplexBooleanExpressionJS
				if((pkcs10.attributes[i].values[j] instanceof asn1js.Utf8String) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.BmpString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.UniversalString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.NumericString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.PrintableString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.TeletexString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.VideotexString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.IA5String) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.GraphicString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.VisibleString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.GeneralString) ||
					(pkcs10.attributes[i].values[j] instanceof asn1js.CharacterString))
				{
					subjval = subjval + ((subjval.length === 0) ? "" : ";") + pkcs10.attributes[i].values[j].valueBlock.value;
				}
				else
					subjval = subjval + ((subjval.length === 0) ? "" : ";") + pkcs10.attributes[i].values[j].constructor.blockName();
			}
			
			const ulrow = `${typeval} ${subjval}`;
			// noinspection InnerHTMLJS
			exten = exten + ulrow;
		}
		

	}
	//endregion
	
	return (subject,exten,sigalgo,keysize);
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Verify existing PKCS#10
//*********************************************************************************
function verifyPKCS10Internal()
{
	//region Decode existing PKCS#10
	const asn1 = asn1js.fromBER(pkcs10Buffer);
	const pkcs10 = new CertificationRequest({ schema: asn1.result });
	//endregion
	
	//region Verify PKCS#10
	return pkcs10.verify();
	//endregion
}
//*********************************************************************************
function verifyPKCS10(pem)
{
	return Promise.resolve().then(() =>
	{
		pkcs10Buffer = stringToArrayBuffer(fromBase64(pem.replace(/(-----(BEGIN|END) CERTIFICATE REQUEST-----|\n)/g, "")));
	}).then(() => verifyPKCS10Internal()).then(result =>
	{
		console.log(`Verification passed: ${result}`);
	}, error =>
	{
        console.log(`Error during verification: ${error}`);
	});
}

//*********************************************************************************
context("Hack for Rollup.js", () =>
{
	return;
	
	// noinspection UnreachableCodeJS
	createPKCS10();
	createPKCS10PEM();
	createPKCS10BER();
	parsePKCS10();
	verifyPKCS10();
	setEngine();
    genKeyHash();
});
//*********************************************************************************
context("PKCS#10 CSR", () =>
{
	//region Initial variables
	const hashAlgs = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
	const signAlgs = ["RSASSA-PKCS1-V1_5", "ECDSA", "RSA-PSS"];
	
	const algorithmsMap = new Map([
		["SHA-1 + RSASSA-PKCS1-V1_5", "1.2.840.113549.1.1.5"],
		["SHA-256 + RSASSA-PKCS1-V1_5", "1.2.840.113549.1.1.11"],
		["SHA-384 + RSASSA-PKCS1-V1_5", "1.2.840.113549.1.1.12"],
		["SHA-512 + RSASSA-PKCS1-V1_5", "1.2.840.113549.1.1.13"],
		
		["SHA-1 + ECDSA", "1.2.840.10045.4.1"],
		["SHA-256 + ECDSA", "1.2.840.10045.4.3.2"],
		["SHA-384 + ECDSA", "1.2.840.10045.4.3.3"],
		["SHA-512 + ECDSA", "1.2.840.10045.4.3.4"],
		
		["SHA-1 + RSA-PSS", "1.2.840.113549.1.1.10"],
		["SHA-256 + RSA-PSS", "1.2.840.113549.1.1.10"],
		["SHA-384 + RSA-PSS", "1.2.840.113549.1.1.10"],
		["SHA-512 + RSA-PSS", "1.2.840.113549.1.1.10"]
	]);
	//endregion
	
	signAlgs.forEach(_signAlg =>
	{
		hashAlgs.forEach(_hashAlg =>
		{
			const testName = `${_hashAlg} + ${_signAlg}`;
			
			it(testName, () =>
			{
				hashAlg = _hashAlg;
				signAlg = _signAlg;
				
				return createPKCS10Internal().then(() =>
				{
					const asn1 = asn1js.fromBER(pkcs10Buffer);
					const pkcs10 = new CertificationRequest({ schema: asn1.result });
					
					assert.equal(pkcs10.signatureAlgorithm.algorithmId, algorithmsMap.get(testName), `Signature algorithm must be ${testName}`);
					
					return verifyPKCS10Internal().then(result =>
					{
						assert.equal(result, true, "PKCS#10 must be verified sucessfully");
					});
				});
			});
		});
	});
});
//*********************************************************************************
