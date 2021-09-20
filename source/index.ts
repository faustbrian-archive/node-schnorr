import { schnorr } from "bcrypto";

export const sign = (hash: string, privateKey: string): string =>
  schnorr.sign(Buffer.from(hash, "hex"), Buffer.from(privateKey, "hex"))
    .toString("hex");

export const verify = (
  hash: string,
  signature: string,
  publicKey: string,
): boolean =>
  schnorr.verify(
    Buffer.from(hash, "hex"),
    Buffer.from(signature, "hex"),
    Buffer.from(publicKey, "hex"),
  );

export const verifyBatch = (hashes: {
  hash: string;
  signature: string;
  publicKey: string;
}[]): boolean => {
  const batch: [Buffer, Buffer, Buffer][] = [];

  for (const hash of hashes) {
    batch.push([
      Buffer.from(hash.hash, "hex"),
      Buffer.from(hash.signature, "hex"),
      Buffer.from(hash.publicKey, "hex"),
    ]);
  }

  return schnorr.verifyBatch(batch);
};
