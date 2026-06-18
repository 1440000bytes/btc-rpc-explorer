"use strict";

const assert = require("assert");
const { analyzeTransaction } = require("./walletFingerprintAnalysis.js");

const lowRSig = "3044" + "0220" + "aa".repeat(32) + "0220" + "aa".repeat(32) + "01";
const highRSig = "3045" + "0221" + "bb".repeat(33) + "0220" + "bb".repeat(32) + "01";
const compressedPk = "02" + "cc".repeat(32);
const uncompressedPk = "04" + "dd".repeat(64);

function p2wpkhInput(txid, vout, sequence, sig, pk) {
	return { txid, vout, sequence, txinwitness: [sig, pk], scriptSig: { asm: "" } };
}

function prevout(type, address, valueBtc) {
	return { scriptPubKey: { type, address }, value: valueBtc };
}

function out(type, address, valueBtc, hex) {
	return { scriptPubKey: { type, address, hex }, value: valueBtc };
}

let pass = 0;
function check(name, cond) {
	assert.ok(cond, name);
	pass++;
	console.log("ok -", name);
}

{
	const tx = {
		version: 2,
		locktime: 839990,
		vin: [p2wpkhInput("aa".repeat(32), 0, 0xfffffffd, lowRSig, compressedPk)],
		vout: [
			out("witness_v0_keyhash", "bc1qchg", 0.00412345, "0014" + "11".repeat(20)),
			out("witness_v0_keyhash", "bc1qpay", 0.005, "0014" + "99".repeat(20))
		]
	};
	const txInputs = { 0: prevout("witness_v0_keyhash", "bc1qin", 0.01) };
	const r = analyzeTransaction(tx, txInputs, 840000, 840000);

	check("electrum: available", r.available === true);
	check("electrum: Core and Electrum among candidates", r.walletCandidates.includes("Bitcoin Core") && r.walletCandidates.includes("Electrum"));
	check("electrum: has signals", r.signals.length > 5);
	check("electrum: anti-fee-sniping signal present", r.signals.some((s) => s.label === "Anti-fee-sniping" && /840|tip/i.test(s.value + s.implication)));
	check("electrum: low-R signal is probabilistic, not a grinding claim", r.signals.some((s) => s.label === "Low-R grinding" && /weak evidence|half the time/.test(s.implication) && !/grinds nonces/.test(s.implication)));
}

{
	const tx = {
		version: 2,
		locktime: 0,
		vin: [p2wpkhInput("ab".repeat(32), 1, 0xffffffff, highRSig, compressedPk)],
		vout: [
			out("witness_v0_keyhash", "bc1qpay", 0.02, "0014" + "22".repeat(20)),
			out("witness_v0_keyhash", "bc1qchg", 0.00499999, "0014" + "33".repeat(20))
		]
	};
	const txInputs = { 0: prevout("witness_v0_keyhash", "bc1qin2", 0.0251) };
	const r = analyzeTransaction(tx, txInputs, 840001, 840002);

	check("coinbase-wallet: Coinbase among candidates", r.walletCandidates.includes("Coinbase Wallet"));
	check("coinbase-wallet: no-RBF signal", r.signals.some((s) => s.label === "RBF signaling" && /No/.test(s.value)));
	check("coinbase-wallet: high-R reliably rules out grinders", r.signals.some((s) => s.label === "Low-R grinding" && /^No \(/.test(s.value) && /33-byte/.test(s.value)));
	check("p2wpkh no-RBF: Blue Wallet discarded (a native segwit Blue Wallet would have signaled RBF)", !r.walletCandidates.includes("Blue Wallet"));
}

{
	const tx = {
		version: 2,
		locktime: 0,
		vin: [p2wpkhInput("ac".repeat(32), 0, 0xffffffff, lowRSig, uncompressedPk)],
		vout: [out("witness_v0_keyhash", "bc1qx", 0.01, "0014" + "44".repeat(20))]
	};
	const txInputs = { 0: prevout("witness_v0_keyhash", "bc1qin3", 0.02) };
	const r = analyzeTransaction(tx, txInputs, 840001, 840002);

	check("uncompressed: no candidates", r.walletCandidates.length === 0);
	check("uncompressed: flagged in signals", r.signals.some((s) => s.label === "Public keys" && /Uncompressed/.test(s.value)));
}

{
	const tx = { version: 1, locktime: 0, vin: [{ coinbase: "deadbeef" }], vout: [out("witness_v0_keyhash", "bc1q", 6.25, "0014" + "55".repeat(20))] };
	const r = analyzeTransaction(tx, {}, 840000, 840000);
	check("coinbase tx: not available", r.available === false);
}

{
	const tx = {
		version: 2,
		locktime: 0,
		vin: [{ txid: "ad".repeat(32), vout: 0, sequence: 0xfffffffd, txinwitness: [], scriptSig: { asm: "" } }],
		vout: [out("witness_v0_keyhash", "bc1qy", 0.01, "0014" + "66".repeat(20))]
	};
	const r = analyzeTransaction(tx, null, 0, 840000);
	check("no-prevout: available", r.available === true);
	check("no-prevout: haveInputData false", r.haveInputData === false);
	check("no-prevout: no low-R/reuse signals", !r.signals.some((s) => s.label === "Low-R grinding" || s.label === "Address reuse"));
}

{
	const tx = {
		version: 2,
		locktime: 0,
		vin: [{ txid: "ae".repeat(32), vout: 0, sequence: 0xfffffffd, txinwitness: ["ab".repeat(64)], scriptSig: { asm: "" } }],
		vout: [out("witness_v1_taproot", "bc1ptr", 0.01, "5120" + "77".repeat(32))]
	};
	const txInputs = { 0: prevout("witness_v1_taproot", "bc1pin", 0.02) };
	const r = analyzeTransaction(tx, txInputs, 840001, 840002);

	check("taproot-only: available", r.available === true);
	check("taproot-only: no low-R signal (no ECDSA sigs examined)", !r.signals.some((s) => s.label === "Low-R grinding"));
}

{
	const tx = {
		version: 2,
		locktime: 0,
		vin: [{ txid: "ba".repeat(32), vout: 0, sequence: 0xffffffff, scriptSig: { asm: lowRSig + " " + compressedPk }, txinwitness: [] }],
		vout: [
			out("pubkeyhash", "1pay", 0.02, "76a914" + "22".repeat(20) + "88ac"),
			out("pubkeyhash", "1chg", 0.00499999, "76a914" + "33".repeat(20) + "88ac")
		]
	};
	const txInputs = { 0: prevout("pubkeyhash", "1in", 0.0251) };
	const r = analyzeTransaction(tx, txInputs, 840001, 840002);

	check("bluewallet legacy p2pkh no-RBF: Blue Wallet still a candidate", r.walletCandidates.includes("Blue Wallet"));
	check("bluewallet legacy p2pkh no-RBF: RBF text mentions Blue Wallet", r.signals.some((s) => s.label === "RBF signaling" && /Blue Wallet/.test(s.implication)));
}

{
	const tx = {
		version: 2,
		locktime: 0,
		vin: [{ txid: "bb".repeat(32), vout: 0, sequence: 0xffffffff, scriptSig: { asm: "" }, txinwitness: [lowRSig, compressedPk] }],
		vout: [out("scripthash", "3pay", 0.01, "a914" + "44".repeat(20) + "87")]
	};
	const txInputs = { 0: prevout("scripthash", "3in", 0.02) };
	const r = analyzeTransaction(tx, txInputs, 840001, 840002);

	check("bluewallet bip49 p2sh no-RBF: Blue Wallet still a candidate", r.walletCandidates.includes("Blue Wallet"));
}

{
	const tx = {
		version: 2,
		locktime: 839995,
		vin: [p2wpkhInput("ca".repeat(32), 0, 0xfffffffd, lowRSig, compressedPk)],
		vout: [
			out("witness_v0_keyhash", "bc1qpay", 0.005, "0014" + "11".repeat(20)),
			out("witness_v0_keyhash", "bc1qchg", 0.00412345, "0014" + "99".repeat(20))
		]
	};
	const txInputs = { 0: prevout("witness_v0_keyhash", "bc1qin", 0.01) };
	const r = analyzeTransaction(tx, txInputs, 840000, 840000);

	check("sparrow: anti-fee-sniping tx keeps Sparrow a candidate", r.walletCandidates.includes("Sparrow"));
}

{
	const tx = {
		version: 2,
		locktime: 0,
		vin: [p2wpkhInput("cb".repeat(32), 0, 0xfffffffd, lowRSig, compressedPk)],
		vout: [
			out("witness_v0_keyhash", "bc1qchg", 0.00412345, "0014" + "99".repeat(20)),
			out("witness_v0_keyhash", "bc1qpay", 0.005, "0014" + "11".repeat(20))
		]
	};
	const txInputs = { 0: prevout("witness_v0_keyhash", "bc1qin", 0.01) };
	const r = analyzeTransaction(tx, txInputs, 840001, 840002);

	check("nunchuk: non-last change keeps Nunchuk (random change position)", r.walletCandidates.includes("Nunchuk"));
	check("nunchuk: non-last change drops the change-last wallets (Sparrow)", !r.walletCandidates.includes("Sparrow"));
}

console.log(`\n${pass} checks passed`);
