import rollupNodeResolve from "rollup-plugin-node-resolve";

export default {
	input: "pkcs10es6.js",
	plugins: [
		rollupNodeResolve({ jsnext: true, main: true })
	],
	output: [
		{
			file: "pkcs10.js",
			format: "iife",
			outro: `
window.createPKCS10PEM = createPKCS10PEM;
window.createPKCS10BER = createPKCS10BER;
window.createPKCS10 = createPKCS10;
window.parsePKCS10 = parsePKCS10;
window.verifyPKCS10 = verifyPKCS10;
window.genKeyHash=genKeyHash;
function context(name, func) {}`
		},
		{
			file: "../../test/browser/pkcs10.js",
			format: "es"
		}
	]
};
