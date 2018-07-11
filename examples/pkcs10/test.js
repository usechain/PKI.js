//var createPKCS10PEM=require("./bundle.js");
var config={
    commonName:"zhouhh hai han",
    countryName:"SG",
    domain:"usechain.net",
    email:"zhouhh@usechain.net",
    iPaddress:"127.0.0.1",
    organizationName:"usechain",
    organizationalUnitName:"usechain sg",
    stateOrProvinceName:"SG state",
    streetAddress:"street sg",
    localityName:"sg  city", //city

}
class KeyPair{
    constructor(privateKey,publicKey){
        this.privateKey=privateKey
        this.publicKey=publicKey

    }
}
class Config{
    constructor(parameters={}) {
        this.commonName=""
        this.countryName=getParametersValue(parameters, "countryName", CSRConfig.defaultValues("countryName"));
        this.hashAlg=getParametersValue(parameters,"hashAlg",CSRConfig.defaultValues("hashAlg"))
        this.signAlg=getParametersValue(parameters,"signAlg",CSRConfig.defaultValues("signAlg"))
        this.email=getParametersValue(parameters,"email",CSRConfig.defaultValues("email"))
        this.domain=getParametersValue(parameters,"domain",CSRConfig.defaultValues("domain"))
        this.anotherdomain=getParametersValue(parameters,"anotherdomain",CSRConfig.defaultValues("anotherdomain"))
        this.iPAddress=getParametersValue(parameters,"iPAddress",CSRConfig.defaultValues("iPAddress"))
        this.organization
        this.organizationalUnit
        this.stateOrProvinceName
        this.streetAddress
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

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}
function arrayBufferToHex(buf){
    var hex="";
    var bufView = new Uint8Array(buf);
    for(var i = 0; i < bufView.length; i++){
        let val =bufView[i].toString(16)
        if(val<16) val ="0"+val
        hex +=val
    }
    return hex;
}

async function createCSR() {
    var id=document.getElementById("idnumber");
    var hashAlg=document.getElementById("hashAlg");
    var signAlg=document.getElementById("signAlg");
    var result=document.getElementById("pem-text-block");
    var hash=await genKeyHash(id.value,"sha-256");
    // Promise.all([hashPromise]).then(v=console.log("hash"))
     config.commonName=arrayBufferToHex(hash)

    //testabc()
    config.hashAlg=hashAlg.options[hashAlg.selectedIndex].value;
    config.signAlg=signAlg.options[signAlg.selectedIndex].value;;

    var pemPromise=createPKCS10PEM(config)
    pemPromise.then((value)=>{ console.log(value)
        result.innerText=value;
        },
        error=>console.error(error))

}


