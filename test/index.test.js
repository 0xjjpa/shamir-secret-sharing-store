const {
  splitWithPasswordAsStore,
  decryptAndCombineWithPassword,
} = require("../");
const { shareSchema } = require("../schema.js");
const crypto = require("crypto");
const { TextEncoder } = require("util");

const TOTAL_SHARES = 3;
const THRESHOLD = 2;
const PASSWORD = "password";
const SECRET = "0xjjpa";

describe("Shamir secret sharing store", () => {
  it("should define a threshold and total property that maches the original threshold used during creation", async () => {
    const encryptedShares = await splitWithPasswordAsStore(
      SECRET,
      PASSWORD,
      TOTAL_SHARES,
      THRESHOLD,
    );
    encryptedShares.map((encryptedShare) =>
      expect(encryptedShare.share.total).toEqual(TOTAL_SHARES),
    );
    encryptedShares.map((encryptedShare) =>
      expect(encryptedShare.share.threshold).toEqual(THRESHOLD),
    );
  });
  it("should have a SHA-512 hash representing the secret value to help match and store the share", async () => {
    const buf = await crypto.webcrypto.subtle.digest(
      "SHA-512",
      new TextEncoder().encode(SECRET),
    );
    const secret_sha512 = Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const encryptedShares = await splitWithPasswordAsStore(
      SECRET,
      PASSWORD,
      TOTAL_SHARES,
      THRESHOLD,
    );
    encryptedShares.map((encryptedShare) =>
      expect(encryptedShare.share.secret_sha512).toEqual(secret_sha512),
    );
  });
  it("should generate shares with the expected schema, and validate them using zod", async () => {
    const encryptedShares = await splitWithPasswordAsStore(
      SECRET,
      PASSWORD,
      TOTAL_SHARES,
      THRESHOLD,
    );
    const parsedSchemas = encryptedShares.map((encryptedShare) =>
      shareSchema.safeParse(encryptedShare),
    );
    parsedSchemas.map((parsedSchema) =>
      expect(parsedSchema.success).toEqual(true),
    );
  });
  it("should be able to create a set of secret shares using a password, and be combined with the same password", async () => {
    const encryptedShares = await splitWithPasswordAsStore(
      SECRET,
      PASSWORD,
      TOTAL_SHARES,
      THRESHOLD,
    );
    const combinedSecret = await decryptAndCombineWithPassword(
      PASSWORD,
      encryptedShares,
    );
    expect(SECRET).toEqual(combinedSecret);
  });
});
