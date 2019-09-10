function getRequiredKeyFromEnv(key: string): string {
  const value = process.env[key];
  if (value === undefined) {
    throw `Required key (${key}) is undefined in env`;
  }
  return value;
}

export const DOMAIN = getRequiredKeyFromEnv('DOMAIN');
