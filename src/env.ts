function isRequired(key: string, value: any): any {
  if (value === undefined) {
    throw `Required key (${key}, ${value}) is undefined in env`;
  }
  return value;
}

// dotenv-webpack seems to require process.env to be accessed with string
// literals, not variables or consts, for its .env replacement to work
export const DOMAIN = isRequired('DOMAIN', process.env['DOMAIN']);
