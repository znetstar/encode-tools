import { Buffer } from 'buffer';
import * as msgpack from '@msgpack/msgpack';
import { nanoid } from 'nanoid';
import {
    v1 as UUIDv1,
    v4 as UUIDv4,
    stringify as UUIDStringify,
    parse as UUIDParse
} from 'uuid';
const  Hashids = require('hashids/cjs');
const base32 = require('base32.js');
const slugid = require('slugid');
const toBuffer = require('typedarray-to-buffer');
import {
    md5,
    sha1,
    sha512,
    sha3,
    xxhash32,
    crc32,
    bcrypt as Bcrypt,
    bcryptVerify,
    xxhash64, BcryptOptions, BcryptVerifyOptions
} from 'hash-wasm';
const ObjSorter = require('node-object-hash/dist/objectSorter');
const LZMA = require('lzma').LZMA;

export enum BinaryEncoding {
    /**
     * Node.js buffer under a compatibility layer for the browser
     */
    nodeBuffer = 'nodeBuffer',
    /**
     * Base64 String
     */
    base64 = 'base64',
    /**
     * Base64 String
     */
    base64url = 'base64url',
    /**
     * Hexadecimal String
     */
    hex = 'hex',
    /**
     * URL-safe base32 string
     */
    base32 = 'base32',
    /**
     * Not recommended, hashids library for backwards compatability
     */
    hashids = 'hashids',
    /**
     * A platform agnostic ArrayBuffer
     */
    arrayBuffer = 'arrayBuffer'
}

export enum HashAlgorithm {
    crc32 = 'crc32',
    xxhash3 = 'xxhash3',
    /**
     * Super fast non-cryptographic hashing algorithm.
     */
    xxhash64 = 'xxhash64',
    /**
     * Super fast non-cryptographic hashing algorithm.
     */
    xxhash32 = 'xxhash32',
    /**
     * Super fast non-cryptographic hashing algorithm.
     */
    /**
     * Insecure hashing algorithm, included for backwards compatibility.
     */
    md5 = 'md5',
    /**
     * SHA2 hashing algorithm.
     */
    sha1 = 'sha1',
    /**
     * SHA2 hashing algorithm.
     */
    sha2 = 'sha2',
    /**
     * SHA3 hashing algorithm.
     */
    sha3 = 'sha3',
    /**
     * BCrypt hashing algorithm
     */
    bcrypt = 'bcrypt'
}

/**
 * Different formats for a unique ID.
 */
export enum IDFormat {
    /**
     * UUID v4, as a Buffer
     */
    uuidv4 = 'uuidv4',
    /**
     * UUID v1, as a Buffer
     */
    uuidv1 = 'uuidv1',
    /**
     * UUID v4 String (with dashes)
     * Example: 710b962e-041c-11e1-9234-0123456789ab
     */
    uuidv4String = 'uuidv4String',
    /**
     * UUID v1 String (with dashes)
     * Example: 710b962e-041c-11e1-9234-0123456789ab
     */
    uuidv1String = 'uuidv1String',
    /**
     * MongoDB BSON ObjectId.
     *
     * Will use native library if available.
     */
    objectId = 'objectId',
    /**
     * 4-character NanoID
     */
    nanoid = 'nanoid',
    /**
     * A JavaScript timestamp
     */
    timestamp = 'timestamp'
}

/**
 * Format for object serialization
 */
export enum SerializationFormat {
    /**
     * JSON
     */
    json = 'json',
    /**
     * Msgpack
     */
    msgpack = 'msgpack',
    /**
     * MongoDB BSON, may throw an error if the object does not contain BSON elements.
     */
    bson = 'bson'
}

export enum CompressionFormat {
  /**
   * LZMA
   */
  lzma = 'lzma'
}

/**
 * Default options for the encoding tools.
 * These will be used if none are passed to the functions used.
 */
export interface EncodingOptions {
    uniqueIdFormat?: IDFormat;
    serializationFormat?: SerializationFormat;
    hashAlgorithm?: HashAlgorithm;
    binaryEncoding?: BinaryEncoding;
    compressionFormat?: CompressionFormat;
}

export class InvalidFormat extends Error {
    constructor(format?: any) {
        super(
            'The format requested'+(
                format ? ' '+format:''
            )+' is not available for this operation'
        );
    }
}

/**
 * The input type commonly acceped by most functions
 */
export type BinaryInputOutput = Buffer|string|ArrayBuffer;

function bufferFrom(...args: any[]): Buffer {
  return (Buffer.from as any)(...args);
}

/**
 * Default options used by encode tools
 */
export const DEFAULT_ENCODE_TOOLS_OPTIONS: EncodingOptions = {
  binaryEncoding: BinaryEncoding.base64,
  hashAlgorithm: HashAlgorithm.xxhash64,
  serializationFormat: SerializationFormat.json,
  uniqueIdFormat: IDFormat.uuidv1String,
  compressionFormat: CompressionFormat.lzma
};

/**
 * Contains tools for encoding/decoding data in different circumstances.
 *
 * Will attempt to use the native version of the underlying algorithm when
 * available.
 */
export class EncodeTools {
    constructor(public options: EncodingOptions = DEFAULT_ENCODE_TOOLS_OPTIONS) {
    }

  /**
   * Always returns the provided data as a `Buffer`, passing the data through `Buffer.from` if not already a Buffer
   *
   * @param n Number of bytes to return
   * @author https://zb.gy/_wpj
   */
    public static ensureBuffer(buf: BinaryInputOutput): Buffer {
        // @ts-ignore
        return Buffer.isBuffer(buf as any) ? buf: bufferFrom(buf as any);
    }

  /**
   * Attempts to load a module if available, or returns null
   *
   * @param n Number of bytes to return
   * @author https://zb.gy/_wpj
   */
    public static safeLoadModule(name: string): any {
        if (typeof(require) === 'undefined')
            return null;
        try {
            return require(name);
        }
        catch (e) {
           return null;
        }
    }

  /**
   * Gets random bytes returning the result as a `Buffer`
   * @param n Number of bytes to return
   */
    public static getRandomBytes(n: number): Buffer {
        let myself = (typeof(window) !== 'undefined' ? window : void(0)) as any;
        if (typeof myself !== 'undefined' && (myself.crypto || myself.msCrypto)) {
            let crypto = (myself.crypto || myself.msCrypto), QUOTA = 65536;
            let a = new Uint8Array(n);
            for (let i = 0; i < n; i += QUOTA) {
                crypto.getRandomValues(a.subarray(i, i + Math.min(n - i, QUOTA)));
            }
            return bufferFrom(a);
        } else {
            return require("crypto").randomBytes(n);
        }
    }

    /**
     * Encodes an `ArrayBuffer` to a node.js `Buffer` using npm:typedarray-to-buffer, and
     * npm:Buffer if node.js Buffer is not available.
     * @param arrayBuffer
     */
    public static arrayBufferToNodeBuffer (arrayBuffer: any): Buffer { return toBuffer(arrayBuffer); }

    /**
     * Encodes a node.js `Buffer` as an `ArrayBuffer`
     * using npm:Buffer if node.js Buffer is not available.
     * @param nodeBuffer
     */
    public static nodeBufferToArrayBuffer(nodeBuffer: BinaryInputOutput): ArrayBuffer { return EncodeTools.ensureBuffer(nodeBuffer).buffer; }

    /**
     * Decodes a hashids string, first to hex, then to a node.js buffer
     * using npm:hashids.
     * @param hashid - Hashid string to decode
     * @param args - Additional arguments to be passed to the `Hashids` constructor
     * in npm:hashids
     */
    public static hashidsToNodeBuffer(hashid: string, ...args: any[]): Buffer {
        const hasher = new Hashids(...args);

        const hex = hasher.decodeHex(hashid);
        return EncodeTools.hexToNodeBuffer(hex);
    }

    /**
     * Encodes a hashids string, from a node.js buffer
     * by first converting to hex and then using npm:hashids.
     * @param hashid - Hashid string to decode
     * @param args - Additional arguments to be passed to the `Hashids` constructor
     * in npm:hashids
     */
    public static nodeBufferToHashids(nodeBuffer: BinaryInputOutput, ...args: any[]): string {
        const hasher = new Hashids(...args);
        const hex = EncodeTools.nodeBufferToHex(EncodeTools.ensureBuffer(nodeBuffer));
        return hasher.encodeHex(hex);
    }

    /**
     * Encodes a hexadecimal string to a node.js buffer.
     * @param hex
     */
    public static hexToNodeBuffer(hex: string): Buffer { return bufferFrom(hex, 'hex'); }
    /**
     * Encodes a node.js buffer as a hexadecimal string.
     * @param hex
     */
    public static nodeBufferToHex(buffer: Buffer): string { return buffer.toString('hex'); }

    /**
     * Encodes a base64 string to a node.js buffer.
     * @param hex
     */
    public static base64ToNodeBuffer(base64: string): Buffer { return bufferFrom(base64, 'base64'); }
    /**
     * Encodes a node.js buffer as a base64 string.
     * @param hex
     */
    public static nodeBufferToBase64(buffer: Buffer): string { return buffer.toString('base64'); }

    /**
     * Encodes a base64url string to a node.js buffer.
     * @author https://zb.gy/ESRN
     * @param hex
     */
    public static base64urlToNodeBuffer(base64url: string): Buffer {
        base64url = (base64url + '==='.slice((base64url.length + 3) % 4))
            .replace(/-/g, '+')
            .replace(/_/g, '/');

        return EncodeTools.base64ToNodeBuffer(base64url);
    }
    /**
     * Encodes a node.js buffer as a base64url string.
     * @author https://zb.gy/ESRN
     * @param hex
     */
    public static nodeBufferToBase64url(buffer: BinaryInputOutput): string {
        let base64url = EncodeTools.nodeBufferToBase64(EncodeTools.ensureBuffer(buffer));
        base64url = base64url.replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
        return base64url;
    }


    /**
     * Encodes a node.js buffer as a base32 string using npm:base32.js
     * @param buffer - Buffer to encode
     * @param args - Additional arguments to be passed to the `Encoder` constructor
     * in npm:base32.js
     */
    public static nodeBufferToBase32(buffer: BinaryInputOutput, ...args: any[]): string {
        const encoder = new base32.Encoder(...args);
        const base32String = encoder.write(EncodeTools.ensureBuffer(buffer)).finalize();
        return base32String;
    }

    /**
     * Encodes a node.js buffer as a base32 string using npm:base32.js
     * @param base32String - Base32 string to decode.
     * @param args - Additional arguments to be passed to the `Decoder` constructor
     * in npm:base32.js
     */
    public static base32ToNodeBuffer(base32String: string, ...args: any[]): Buffer {
        const decoder = new base32.Decoder(...args);
        const bytes = decoder.write(base32String).finalize();
        return bufferFrom(bytes);
    }

    /**
     * Encodes binary data using the provided format returning either a node.js buffer, array buffer, or string
     * @param buffer
     * @param format
     */
    public encodeObject(inputObject: any, format?: BinaryEncoding, ...args: any[]): Buffer;
    public encodeObject(inputObject: any, format?: BinaryEncoding, ...args: any[]): ArrayBuffer;
    public encodeObject(inputObject: any, format?: BinaryEncoding, ...args: any[]): string;
    public encodeObject(inputObject: any, format = this.options.binaryEncoding, ...args: any[]): BinaryInputOutput {
        const buffer: Buffer = EncodeTools.ensureBuffer(
            this.serializeObject(inputObject)
        );

        return this.encodeBuffer(
            buffer,
            format,
            ...args
        );
    }

    /**
     * Decodes binary data from the provided format returning either a node.js buffer.
     * @param buffer
     * @param format
     */
    public decodeObject(buffer: ArrayBuffer, format?: BinaryEncoding, ...args: any[]): any;
    public decodeObject(buffer: Buffer, format?: BinaryEncoding, ...args: any[]): any;
    public decodeObject(input: string, format?: BinaryEncoding, ...args: any[]): any;
    public decodeObject(inputBuffer: BinaryInputOutput, format = this.options.binaryEncoding, ...args: any[]): any {
        const buffer: Buffer = this.decodeBuffer(EncodeTools.ensureBuffer(inputBuffer), format, ...args);
        return this.deserializeObject(buffer);
    }

    /**
     * Encodes binary data using the provided format returning either a node.js buffer, array buffer, or string
     * @param buffer
     * @param format
     */
    public encodeBuffer(inputBuffer: BinaryInputOutput, format?: BinaryEncoding, ...args: any[]): Buffer;
    public encodeBuffer(inputBuffer: BinaryInputOutput, format?: BinaryEncoding, ...args: any[]): ArrayBuffer;
    public encodeBuffer(inputBuffer: BinaryInputOutput, format?: BinaryEncoding, ...args: any[]): string;
    public encodeBuffer(inputBuffer: BinaryInputOutput, format = this.options.binaryEncoding, ...args: any[]): BinaryInputOutput {
        const buffer: Buffer = EncodeTools.ensureBuffer(inputBuffer);
        if (format === BinaryEncoding.nodeBuffer) return buffer;
        else if (format === BinaryEncoding.arrayBuffer) return EncodeTools.nodeBufferToArrayBuffer(buffer);
        else if (format === BinaryEncoding.base64) return EncodeTools.nodeBufferToBase64(buffer);
        else if (format === BinaryEncoding.base64url) return EncodeTools.nodeBufferToBase64url(buffer);
        else if (format === BinaryEncoding.base32) return EncodeTools.nodeBufferToBase32(buffer);
        else if (format === BinaryEncoding.hashids) return EncodeTools.nodeBufferToHashids(buffer, ...args);
        else if (format === BinaryEncoding.hex) return EncodeTools.nodeBufferToHex(buffer);
        throw new InvalidFormat(format);
    }

    /**
     * Decodes binary data from the provided format returning either a node.js buffer.
     * @param buffer
     * @param format
     */
    public decodeBuffer(buffer: ArrayBuffer, format?: BinaryEncoding, ...args: any[]): Buffer;
    public decodeBuffer(buffer: Buffer, format?: BinaryEncoding, ...args: any[]): Buffer;
    public decodeBuffer(input: string, format?: BinaryEncoding, ...args: any[]): Buffer;
    public decodeBuffer(buffer: BinaryInputOutput, format = this.options.binaryEncoding, ...args: any[]): Buffer {
        if (format === BinaryEncoding.nodeBuffer)
            return bufferFrom(buffer);
        else if (format === BinaryEncoding.arrayBuffer) return EncodeTools.arrayBufferToNodeBuffer(buffer);
        else if (format === BinaryEncoding.base64) return EncodeTools.base64ToNodeBuffer(buffer.toString());
        else if (format === BinaryEncoding.base64url) return EncodeTools.base64urlToNodeBuffer(buffer.toString());
        else if (format === BinaryEncoding.base32) return EncodeTools.base32ToNodeBuffer(buffer.toString());
        else if (format === BinaryEncoding.hashids) return EncodeTools.hashidsToNodeBuffer(buffer.toString(), ...args);
        else if (format === BinaryEncoding.hex) return EncodeTools.hexToNodeBuffer(buffer.toString());
        throw new InvalidFormat(format);
    }

    public static async crc32(buffer: BinaryInputOutput): Promise<Buffer> {
        return bufferFrom(await crc32(EncodeTools.ensureBuffer(buffer)));
    }

    /* Hashing functions */
    /**
     * Hashes using XXHash-32 (https://zb.gy/l4kN), a fast, non-cryptographic,
     * hashing function.
     *
     * Uses XXHash from npm:hash-wasm
     * @param buffer
     * @param args
     */
    public static async xxhash32(buffer: BinaryInputOutput, ...args: any[]): Promise<Buffer> {
        return bufferFrom(await xxhash32(EncodeTools.ensureBuffer(buffer), ...args));
    }
    /**
     * Hashes using XXHash-64 (https://zb.gy/l4kN), a fast, non-cryptographic,
     * hashing function.
     *
     * Uses XXHash from npm:hash-wasm
     * @param buffer
     * @param args
     */
    public static async xxhash64(buffer: BinaryInputOutput, ...args: any[]): Promise<Buffer> {
        return bufferFrom(await xxhash64(EncodeTools.ensureBuffer(buffer), ...args));
    }
    /**
     * Uses the very popular, but UNSAFE, SHA-1 cryptographic algorithm.
     * Use SHA3 for new projects.
     *
     * Uses SHA1 from npm:hash-wasm
     * @param buffer
     * @param args
     */
    public static async sha1(buffer: BinaryInputOutput): Promise<Buffer> { return bufferFrom(await sha1(EncodeTools.ensureBuffer(buffer))); }
    /**
     * Uses the popular, but UNSAFE, 512bit SHA-2 cryptographic algorithm.
     * Use SHA3 for new projects.
     *
     * Uses 512bit SHA from npm:hash-wasm
     * @param buffer
     * @param args
     */
    public static async sha2(buffer: BinaryInputOutput): Promise<Buffer> { return bufferFrom(await sha512(EncodeTools.ensureBuffer(buffer))); }
    /**
     * Uses the new SHA-3 cryptographic algorithm.
     *
     * Uses SHA-3 from npm:hash-wasm
     * @param buffer
     * @param args
     */
    public static async sha3(buffer: BinaryInputOutput): Promise<Buffer> { return bufferFrom(await sha3(EncodeTools.ensureBuffer(buffer))); }
    /**
     * Uses the very popular, but VERY VERY UNSAFE, MD5 cryptographic algorithm.
     * Use SHA3 for new projects.
     *
     * Uses MD5 from npm:hash-wasm
     * @param buffer
     * @param args
     */
    public static async md5(buffer: BinaryInputOutput): Promise<Buffer> { return bufferFrom(await md5(EncodeTools.ensureBuffer(buffer))); }

  /**
   * Hashes using bcrypt
   * @param buffer
   * @param args
   */
    public static async bcrypt(buffer: BinaryInputOutput, options?: BcryptOptions): Promise<Buffer> {
        options = (options || {}) as any;
        options.password = bufferFrom(buffer).toString('utf8');
        if (!options.salt)
            options.salt = EncodeTools.getRandomBytes(16);
        if (!options.costFactor)
            options.costFactor = 11;
        if (!options.outputType)
            options.outputType = 'encoded';

        let key = await Bcrypt(options);

        return bufferFrom(EncodeTools.ensureBuffer(key));
    }

  /**
   * Compares a password with bcrypt
   * @param buffer
   * @param args
   */
    public static async bcryptVerify(password: BinaryInputOutput, hash: BinaryInputOutput, options: BcryptVerifyOptions = ({} as any)): Promise<boolean> {
        const hashString = (EncodeTools.ensureBuffer(hash).toString('utf8'));

        options.password = EncodeTools.ensureBuffer(password);
        options.hash = hashString;

        return bcryptVerify(options);
    }


    /**
     * Hashes data using the provided algorithm, returning a node.js Buffer.
     *
     * @param buffer
     * @param algorithm
     */
    public async hash(buffer: BinaryInputOutput, algorithm: HashAlgorithm = this.options.hashAlgorithm, ...args: any[]): Promise<Buffer> {
        if (algorithm === HashAlgorithm.xxhash64) return EncodeTools.xxhash64(buffer, ...args);
        else if (algorithm === HashAlgorithm.xxhash32) return EncodeTools.xxhash32(buffer, ...args);
        else if (algorithm === HashAlgorithm.sha1) return EncodeTools.sha1(buffer);
        else if (algorithm === HashAlgorithm.sha2) return EncodeTools.sha2(buffer);
        else if (algorithm === HashAlgorithm.sha3) return EncodeTools.sha3(buffer);
        else if (algorithm === HashAlgorithm.md5) return EncodeTools.md5(buffer);
        else if (algorithm === HashAlgorithm.bcrypt) return EncodeTools.bcrypt(buffer, ...args);
        else if (algorithm === HashAlgorithm.crc32) return EncodeTools.crc32(buffer);
        throw new InvalidFormat(algorithm);
    }

    /**
     * Hashes data using the provided algorithm, returning a node.js Buffer.
     *
     * @param buffer
     * @param algorithm
     */
    public async hashString(buffer: Buffer, algorithm: HashAlgorithm = this.options.hashAlgorithm, ...args: any[]): Promise<string> {
        return (await this.hash(buffer, algorithm, ...args)).toString('utf8');
    }

    /**
     * Hashes an object using the provided algorithm, returning a node.js Buffer.
     *
     * @param buffer
     * @param algorithm
     */
    public async hashObject(obj: any, algorithm: HashAlgorithm = this.options.hashAlgorithm, ...args: any[]): Promise<Buffer> {
        // @ts-ignore
        let sorter = ObjSorter();

        let buffer = bufferFrom(
            sorter(obj)
        );
        return (await this.hash(buffer, algorithm, ...args));
    }

  /**
   * Generates a v1 UUID, returning the bytes as an array of numbers
   *
   * @param buffer
   * @param algorithm
   */
    protected static uuidv1Array(): number[] {
        const buf: number[] = [];
        UUIDv1(void(0), buf, 0);
        return buf;
    }

  /**
   * Generates a v4 UUID, returning the bytes as an array of numbers
   *
   * @param buffer
   * @param algorithm
   */
    protected static uuidv4Array(): number[] {
        const buf: number[] = [];
        UUIDv4(void(0), buf, 0);
        return buf;
    }


  /**
   * Generates an ID using nanoid
   *
   * @param size Size of the id (in characters)
   */
    public static nanoid(size?: number): string {
        return nanoid(size);
    }
  /**
   * Returns a JavaScript timestamp (in milliseconds)
   */

    public static timestamp(): number {
        return (new Date()).getTime();
    }

  /**
   * Generates a v1 UUID, returning the bytes as a `Buffer`
   *
   */
    public static uuidv1(): Buffer {
        return bufferFrom(EncodeTools.uuidv1Array(), 0);
    }

  /**
   * Generates a v4 UUID, returning the bytes as a `Buffer`
   *
   */
    public static uuidv4(): Buffer {
        return bufferFrom(EncodeTools.uuidv4Array(), 0);
    }

  /**
   * Generates a v1 UUID, returning the bytes as a hexadecimal string in the traditional format (with dashes "-").
   *
   */
    public static uuidv1String(): string {
        return UUIDStringify(EncodeTools.uuidv1Array(), 0);
    }

  /**
   * Generates a v4 UUID, returning the bytes as a hexadecimal string in the traditional format (with dashes "-").
   *
   */
    public static uuidv4String(): string {
        return UUIDStringify(EncodeTools.uuidv4Array(), 0);
    }

  /**
   * Decodes a UUID encoded as a slugid returning the bytes as a `Buffer`
   *
   * @param id SlugID encoded UUID
   */
    public static decodeSlugID(id: string): Buffer {
        return bufferFrom(UUIDParse(slugid.decode(id)));
    }

  /**
   * Decodes a UUID encoded as a slugid returning the bytes as a `Buffer`
   *
   * @param uuid UUID as a `Buffer`
   */
    public static encodeSlugID(uuid: Buffer): string {
        return slugid.encode(UUIDStringify( uuid ));
    }

  /**
   * Returns an instance of the `bson` node module, using the native `bson-ext` if available.
   *
   */
    protected static get bson(): any {
        let bson = EncodeTools.safeLoadModule('bson-ext');
        if (!bson)
            bson = require('bson');
        return bson;
    }

  /**
   * Returns an instance of the `ObjectId` constructor `bson` node module, using the native `bson-ext` if available.
   *
   */
    public static get ObjectId() {
      return this.bson.ObjectId;
    }

  /**
   * Creates a new ObjectId returning the bytes as a `Buffer`
   *
   */
    public static newObjectId(): Buffer { return (new (EncodeTools.ObjectId)()).id; }

  /**
   * Generates a unique ID using one of the available algorithms, returning the result as a Buffer, string or number.
   *
   * @param idFormat Algorithm to use to generate the unique id
   * @param args Extra args to pass to the ID generation function
   */
    public uniqueId(idFormat?: IDFormat): Buffer|string|number;
    public uniqueId(idFormat?: IDFormat, ...args: any[]): Buffer|string|number;
    public uniqueId(idFormat: IDFormat = this.options.uniqueIdFormat, ...args: any[]): Buffer|string|number {
        if (idFormat === IDFormat.uuidv1) return EncodeTools.uuidv1();
        else if (idFormat === IDFormat.uuidv4) return EncodeTools.uuidv4();
        else if (idFormat === IDFormat.uuidv1String) return EncodeTools.uuidv1String();
        else if (idFormat === IDFormat.uuidv4String) return EncodeTools.uuidv4String();
        else if (idFormat === IDFormat.objectId) return EncodeTools.newObjectId();
        else if (idFormat === IDFormat.timestamp) return EncodeTools.timestamp();
        else if (idFormat === IDFormat.nanoid) return EncodeTools.nanoid(...args);
        throw new InvalidFormat(idFormat);
    }

  /**
   * Serializes data as a JSON encoded string
   *
   * @param obj Object to serialize
   */
    public static objectToJson<T>(obj: T): string { return JSON.stringify(obj); }
  /**
   * Deserializes a JSON encoded string to an `object`
   *
   * @param data JSON to deserialize
   */
    public static jsonToObject<T>(data: string|Buffer): T { return JSON.parse(EncodeTools.ensureBuffer(data).toString('utf8')) as T; }

  /**
   * Serializes data as msgpack, returning the result as a `Buffer`
   *
   * @param obj Object to serialize
   */
    public static objectToMsgpack<T>(obj: T): Buffer { return bufferFrom(msgpack.encode(obj)); }
  /**
   * Deserializes a msgpack encoded Buffer to an `object`
   *
   * @param data msgpack to deserialize
   */
    public static msgpackToObject<T>(data: Buffer): T { return msgpack.decode<T>(data) as T; }

  /**
   * Serializes data as BSON, returning the result as a `Buffer`
   *
   * @param obj Object to serialize
   */
    public static objectToBson<T>(obj: T): Buffer { return this.bson.serialize(obj); }
  /**
   * Deserializes a BSON encoded Buffer to an `object`
   *
   * @param data BSON to deserialize
   */
    public static bsonToObject<T>(bson: Buffer): T { return this.bson.deserialize(bson) as T; }

  /**
   * Serializes an object using one of the available algorithms, returning the result as a Buffer or a string
   *
   * @param obj Object to serialize
   * @param serializationFormat - Algorithm to serialize with
   */
    public serializeObject<T>(obj: T, serializationFormat: SerializationFormat = this.options.serializationFormat): Buffer|string {
        if (serializationFormat === SerializationFormat.json) return EncodeTools.objectToJson<T>(obj);
        else if (serializationFormat === SerializationFormat.msgpack) return EncodeTools.objectToMsgpack<T>(obj);
        else if (serializationFormat === SerializationFormat.bson) return EncodeTools.objectToBson<T>(obj);
        throw new InvalidFormat(serializationFormat);
    }
  /**
   * Deserializes an object serialized using one of the available algorithms, returning the result as an object
   *
   * @param data Data to deserialize
   * @param serializationFormat - Algorithm to deserialize with
   */
    public deserializeObject<T>(data: Buffer|string, serializationFormat: SerializationFormat = this.options.serializationFormat): T {
        if (serializationFormat === SerializationFormat.json) return EncodeTools.jsonToObject<T>(data.toString()) as T;
        else if (serializationFormat === SerializationFormat.msgpack) return EncodeTools.msgpackToObject<T>(bufferFrom(data)) as T;
        else if (serializationFormat === SerializationFormat.bson) return EncodeTools.bsonToObject<T>(bufferFrom(data)) as T;
        throw new InvalidFormat(serializationFormat);
    }

  /**
   * Compresses a buffer using LZMA
   * @param buf - Buffer
   * @param mode - Compression mode (1-9)
   */
    public static async compressLZMA(buf: Buffer, mode: number): Promise<Buffer> {
      let lzma = new LZMA();
      return new Promise<Buffer>((resolve, reject) => {
        lzma.compress(buf, mode, (result: any, error: any) => {
          if (error) reject(error);
          else resolve(EncodeTools.ensureBuffer(result));
        });
      });
    }

  /**
   * Decompresses a buffer using LZMA
   * @param buf - Buffer
   * @param mode - Compression mode (1-9)
   */
    public static async decompressLZMA(buf: Buffer): Promise<Buffer> {
      let lzma = new LZMA();
      return new Promise<Buffer>((resolve, reject) => {
        lzma.decompress(buf, (result: any, error: any) => {
          if (error) reject(error);
          else resolve(EncodeTools.ensureBuffer(result));
        });
      });
    }

  /**
   * Compresses arbitrary data using the provided format and any options
   * @param data - Data to compress
   * @param format - Format to use
   * @param args - Options
   */
    public async compress(data: BinaryInputOutput, format: CompressionFormat = CompressionFormat.lzma, ...args: any[]): Promise<Buffer> {
      if (format === CompressionFormat.lzma) {
        return EncodeTools.compressLZMA(EncodeTools.ensureBuffer(data), args[0]);
      }
      throw new InvalidFormat(format);
    }

  /**
   * Decompresses arbitrary data using the provided format and any options
   * @param data - Data to decompress
   * @param format - Format to use
   */
    public async decompress(data: BinaryInputOutput, format: CompressionFormat = CompressionFormat.lzma, ...args: any[]): Promise<Buffer> {
      if (format === CompressionFormat.lzma) {
        return EncodeTools.decompressLZMA(EncodeTools.ensureBuffer(data));
      }
      throw new InvalidFormat(format);
    }

  /**
   * Returns an EncodeTools instance with the default properties
   */
    public static get WithDefaults() {
        return new EncodeTools();
    }
  /**
   * Creates an an EncodeTools instance with the provided properties
   */
    public static create(options?: EncodingOptions): EncodeTools {
        return new EncodeTools(options);
    }
}

export default EncodeTools;
