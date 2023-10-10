import { decryptAndCombineWithPassword, splitWithPasswordAsStore } from "../src";

async function main() {
  // Usage:
  const secret = "This is a secret";
  console.log("Pre-split secret", secret);
  const password = "password";
  const encryptedShares = await splitWithPasswordAsStore(secret, password, 3, 2);
  console.log("Encrypted Shares", encryptedShares);
  const originalSecret = await decryptAndCombineWithPassword(password, encryptedShares);
  console.log("Original Secret", originalSecret);
}

console.log(Date.now());

main();