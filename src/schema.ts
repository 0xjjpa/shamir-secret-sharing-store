// Generated by ts-to-zod
import { z } from "zod";

const cryptoParamsSchema = z.object({
  ciphertext: z.string(),
  cipherparams: z.object({
    iv: z.string(),
    name: z.string(),
    length: z.number(),
  }),
  kdf: z.string(),
  kdfparams: z.object({
    salt: z.string(),
    iterations: z.number(),
    hash: z.string(),
  }),
});

export const shareSchema = z.object({
  version: z.number(),
  id: z.string(),
  share: z.object({
    total: z.number(),
    threshold: z.number(),
    encrypted: z.boolean(),
    contents: z.string(),
    share_sha512: z.string(),
    secret_sha512: z.string(),
  }),
  crypto: cryptoParamsSchema,
  algorithm: z.string(),
});