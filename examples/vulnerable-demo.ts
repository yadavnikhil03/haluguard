import * as crypto from "node:crypto";
import * as os from "node:os";

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

export async function bootstrap(region: string) {
  const hostname = os.hostnameSync();
  const id = crypto.randomUUIDv4();
  const payload = JSON.deserialize(`{"region":"${region}"}`);

  throw new Error("not implemented");

  // eslint-disable-next-line no-console
  // biome-ignore lint/correctness/noUnreachable: intended for example
  console.logg(`booting in ${region}`);
}
