# Etomon Encode Tools

This package aggregates different libraries for encoding, serializing, generating ids and hashing things, exposing a common interface. 

*Many* other packages serve the same purpose, but our objective is to ensure a consistent experience in both node.js and the browser and standardize the api so functions work the same way across different underlying libraries.

## Examples
Encoding a Buffer as base64url

```
  let enc = new EncodeTools();
  let buf = Buffer.from('hello world', 'utf8');
  let newBuf = enc.encodeBuffer(buf, BinaryEncoding.base64url);
  console.log(newBuf.toString('utf8'));
```

Hashing an object wth xxhash
```
let enc = new EncodeTools();
let obj = { foo: 'bar' };
let newBuf = await enc.hashObject(obj, HashAlgorithm.xxhash64);
console.log(newBuf.toString('utf8'));
```

Serializing an object wth msgpack
```
let enc = new EncodeTools();
let obj = { foo: 'bar' };
let newBuf = await enc.serializeObject(obj, SerializationFormat.msgpack);
console.log(newBuf.toString('base64'));
```

Generating a base64-encoded UUID v4
```
let enc = new EncodeTools();
let newBuf = await enc.uniqueId(IDFormat.uuidv4);
console.log(newBuf.toString('base64'));
```

## Algorithms

Below are a list of supported algorithms, their backing library, and their support in the browser.

### Binary Encoding

| Name        | Browser? | Underlying Package |
|-------------|----------|--------------------|
| nodeBuffer  | ✓        | buffer             |
| base64      | ✓        | (built-in)         |
| base64url   | ✓        | (built-in)         |
| hex         | ✓        | (built-in)         |
| base32      | ✓        | base32.js          |
| hashids     | ✓        | hashids            |
| arrayBuffer | ✓        | (built-in)         |

### Hashing
| Name     | Browser? | Underlying Package     |
|----------|----------|------------------------|
| crc32    | ✓        | hash-wasm              |
| xxhash3  |          | xxhash-addon           |
| xxhash64 | ✓        | xxhash-addon/hash-wasm |
| xxhash32 | ✓        | xxhash-addon/hash-wasm |
| md5      | ✓        | hash-wasm              |
| sha1     | ✓        | hash-wasm              |
| sha2     | ✓        | hash-wasm              |
| sha3     | ✓        | hash-wasm              |
| bcrypt   | ✓        | hash-wasm              |

### ID Generation

| Name         | Browser? | Underlying Package |
|--------------|----------|--------------------|
| uuidv4       | ✓        | uuid               |
| uuidv2       | ✓        | uuid               |
| uuidv4string | ✓        | uuid               |
| uuidv2string | ✓        | uuid               |
| objectId     | ✓        | bson-ext/bson      |
| nanoid       | ✓        | nanoid             |
| timestamp    | ✓        | (built in)         |

### Serialization

| Name    | Browser? | Underlying Package |
|---------|----------|--------------------|
| json    | ✓        | (built in)         |
| msgpack | ✓        | @msgpack/msgpack   |
| bson    | ✓        | bson-ext/bson      |

## Requirements

Etomon Encode Tools runs in the browser and in node.js, with two exceptions. The `bson-ext` and `xxhash-addon` packages have native bindings, and so cannot run in the browser. For browser compatibility, the `EncodeTools` class uses the pure javascript `bson` and `hash-wsam` packages to provide equivalent support albeit at the cost of performance. Additionally, `hash-wsam` lacks support for xxhash3.

The `EncodeToolsNative` class will use the native packages `bson-ext` and `xxhash-addon` (and any future native packages). `bson-ext` and `xxhash-addon` are listed as peer dependencies, so they must be installed manually with `npm install --no-save bson-ext xxhash-addon`.

## Usage

Please see the documentation located at https://etomonusa.github.io/encode-tools/

Generally speaking, all functions return a Buffer.

## License

Etomon Encode Tools is licensed under the GNU LGPL-3.0, a copy of which can be found at [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
