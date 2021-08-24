import {assert} from 'chai';
import {Chance} from 'chance';
import {Buffer} from 'buffer';
import {
  BinaryEncoding,
  BinaryInputOutput, DEFAULT_ENCODE_TOOLS_OPTIONS,
  EncodeTools,
  EncodeToolsFormat,
  EncodeToolsFunction,
  HashAlgorithm,
  IDFormat, ImageFormat, ImageFormatMimeTypes, MimeTypesImageFormat, MimeTypesSerializationFormat,
  SerializationFormat, SerializationFormatMimeTypes
} from '../../EncodeTools';
import * as _ from 'lodash';
import * as hashWasm from "hash-wasm";
import {BcryptOptions} from "hash-wasm";
import {serialize as BSONSerialize} from 'bson';
const cborX = require('cbor-x');

const ZstdCodec = require('zstd-codec').ZstdCodec;
const LZMA = require('lzma').LZMA;
import {parse as UUIDParse, stringify as UUIDStringify} from "uuid";
import * as msgpack from "@msgpack/msgpack";
import {EncodeOptions} from "@msgpack/msgpack";
import {
  CompressRunner,
  EncodeBufferRunner,
  EncodeObjectRunner,
  EncodeToolsRunner,
  HashObjectRunner,
  HashRunner,
  HashStringRunner,
  ImageBrightnessRunner,
  ImageConvertRunner,
  ImageCropRunner,
  ImageResizeRunner, ImageRunnerBase,
  randomBuffer,
  randomObject,
  randomOptions,
  SerializeObjectRunner
} from "../common/EncodeToolsRunner";


const slugid = require('slugid');


const toBuffer = require('typedarray-to-buffer');
const  Hashids = require('hashids/cjs');

const base32 = require('base32.js');
const Jimp = require('jimp');

describe('MimeTypesImageFormat', async function  () {
  it('should have the same entries as ImageFormatMimeType except the key and value reversed', async function () {
    assert.deepEqual(
      Array.from(MimeTypesImageFormat.entries()),
      Array.from(ImageFormatMimeTypes.entries())
        .map(([k,v]) => [v,k]),
    );
  });
});

describe('MimeTypesSerializationFormat', async function  () {
  it('should have the same entries as SerializationFormatMimeTypes except the key and value reversed', async function () {
    assert.deepEqual(
      Array.from(MimeTypesSerializationFormat.entries()),
      Array.from(SerializationFormatMimeTypes.entries())
        .map(([k,v]) => [v,k]),
    );
  });
});

describe('EncodeTools', async function () {
  let chance = Chance();

  let tests: EncodeToolsRunner<any, any, any, any>[] = [
    new EncodeBufferRunner(),
    new HashObjectRunner(),
    new HashStringRunner(),
    new HashRunner(),
    new SerializeObjectRunner(),
    new EncodeObjectRunner(),
    new CompressRunner(),
    new ImageResizeRunner(),
    new ImageCropRunner(),
    new ImageConvertRunner(),
    new ImageBrightnessRunner()
  ];

  describe('ensureBuffer', async function () {
    it('should convert string to a Buffer, and Buffer should contain the same data', async function () {
      let str = chance.string();
      assert.isString(str);

      let buf = EncodeTools.ensureBuffer(str);
      assert.isTrue(Buffer.isBuffer(buf), 'Did not return buffer from string');

      let dif = Buffer.compare(
        Buffer.from(str, 'utf8'),
        buf
      );

      assert.equal(dif, 0, 'Returned Buffer is not the same');
    });

    it('should convert an ArrayBuffer to a Buffer', async function () {
      let inBuf = Buffer.from(chance.string(), 'utf8');
      let arrayBuffer = inBuf.buffer;

      let buf = EncodeTools.ensureBuffer(arrayBuffer);
      assert.isTrue(Buffer.isBuffer(buf), 'Did not return buffer from array buffer');
      assert.isTrue(
        (
          buf.equals(new Uint8Array(arrayBuffer))
        ),
        'Returned Buffer is not the same'
      );
    });

    it('should return the same Buffer given a Buffer', async function () {
      let buffer = Buffer.from(chance.string(), 'utf8');

      let buf = EncodeTools.ensureBuffer(buffer);
      assert.isTrue(Buffer.isBuffer(buf), 'Did not return buffer from buffer');

      assert.isTrue((
        buf.equals(buffer)
      ),  'Returned Buffer is not the same');
    });
  });
  describe('saleLoadModule', async function () {
    it('should return null if a module cannot be found', async function () {
      let fn = () => {};
      try {
        let val = EncodeTools.safeLoadModule(chance.string({ symbols: false }));

        assert.isNull(val, 'Value returned was not null');
      } catch (err) {
        fn = () => { throw err; }
      } finally {
        assert.doesNotThrow(fn);
      }
    });
  });

  describe('getRandomBytes', async function () {
    it('should create a buffer with random data', async function () {
      let num = chance.integer({ min: 1, max: 5e3 });
      let buf = EncodeTools.getRandomBytes(num);

      assert.isTrue(Buffer.isBuffer(buf), 'Did not return a buffer');
      assert.equal(buf.byteLength, num, 'Buffer was not the requested size');
    });
  });



  describe('arrayBufferToNodeBuffer', async function () {
    it('should return a buffer for a given array buffer', async function () {
      let inBuf = Buffer.from(chance.string(), 'utf8');

      let buf = EncodeTools.arrayBufferToNodeBuffer(inBuf);
      assert.isTrue(Buffer.isBuffer(buf), 'Function did not return an arraybuffer');
      assert.isTrue(
        inBuf.equals(buf),
        'Buffer returned is not the same'
      );
    });
  });

  describe('nodeBufferToArrayBuffer', async function () {
    it('should return a arraybuffer for a given buffer', async function () {
      let inBuf = Buffer.from(chance.string(), 'utf8');

      let buf = EncodeTools.nodeBufferToArrayBuffer(inBuf);
      assert.instanceOf(buf, ArrayBuffer, 'Function did not return an arraybuffer');

      assert.isTrue(
        inBuf.equals(new Uint8Array(buf)),
        'Buffer returned is not the same'
      );
    });
  });

  describe('hashidsToNodeBuffer', async function () {
    it('should return a number, as a string, given a hashids buffer', async function () {
      let hasher  = new Hashids();
      let number = (chance.integer({ min: 1 })).toString(16);
      let hash = hasher.encodeHex(number);
      let buf1 = Buffer.from(number, 'hex');
      let buf2 = EncodeTools.hashidsToNodeBuffer(hash);

      assert.isTrue(Buffer.isBuffer(buf2));

      assert.isTrue(buf1.equals(buf2), 'Buffers are not the same');
    });
  });

  describe('nodeBufferToHashids', async function () {
    it('should produce a hashids buffer, given a number as a string', async function () {
      let salt = chance.string();
      let number = (chance.integer({ min: 1 })).toString(16);
      let buf = Buffer.from(number, 'hex');
      number = buf.toString('hex');
      let hasher  = new Hashids(salt);
      let hash1 = hasher.encodeHex(number);
      let hash2 = EncodeTools.nodeBufferToHashids(buf, salt);

      assert.equal(hash2, hash1, 'Hashids string is not the same');
    });
  });


  describe('hexToNodeBuffer', async function () {
    it('should return a hexadecimal representation of data', async function () {
      let number = (chance.integer({ min: 1 })).toString(16);
      let buf1 = Buffer.from(number, 'hex');
      let buf2 = EncodeTools.hexToNodeBuffer(number);

      assert.isTrue(Buffer.isBuffer(buf2));

      assert.isTrue(
        buf1.equals(buf2),
        'Buffers were not equal'
      );
    });
  });

  describe('nodeBufferToHex', async function () {
    it('should return data from its hexadecimal representation', async function () {
      let number = (chance.integer({ min: 1 })).toString(16);
      let buf = Buffer.from(number, 'hex');
      number = buf.toString('hex');
      let hex1 = number;
      let hex2 = EncodeTools.nodeBufferToHex(buf);

      assert.equal(
        hex2,
        hex1,
        'Hex string were not equal'
      );
    });
  });

  describe('base64ToNodeBuffer', async function () {
    it('should return a base64 representation of data', async function () {
      let buf1 = Buffer.from(chance.string());
      let str1 = buf1.toString('base64');
      let buf2 = EncodeTools.base64ToNodeBuffer(str1);

      assert.isTrue(Buffer.isBuffer(buf2));

      assert.isTrue(
        buf1.equals(buf2),
        'Buffers were not equal'
      );
    });
  });

  describe('nodeBufferToBase64', async function () {
    it('should return data from its base64 representation', async function () {
      let buf1 = Buffer.from(chance.string());
      let str1 = buf1.toString('base64');
      let str2 = EncodeTools.nodeBufferToBase64(buf1);

      assert.equal(
        str2,
        str1,
        'Base64 strings were not equal'
      );
    });
  });

  describe('base64urlToNodeBuffer', async function () {
    it('should return a base64url representation of data', async function () {
      let buf1 = Buffer.from(chance.string());
      let str1 = buf1.toString('base64');
      str1 = str1.replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')

      let buf2 = EncodeTools.base64urlToNodeBuffer(str1);

      assert.isTrue(Buffer.isBuffer(buf2));

      assert.isTrue(
        buf1.equals(buf2),
        'Buffers were not equal'
      );
    });
  });

  describe('nodeBufferToBase64url', async function () {
    it('should return data from its base64url representation', async function () {
      let buf1 = Buffer.from(chance.string());
      let str1 = buf1.toString('base64');
      str1 = str1.replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')

      let str2 = EncodeTools.nodeBufferToBase64url(buf1);

      assert.equal(
        str2,
        str1,
        'Base64URL strings were not equal'
      );
    });
  });

  describe('base32urlToNodeBuffer', async function () {
    it('should return a base32 representation of data', async function () {
      let buf1 = Buffer.from(chance.string());

      const encoder = new base32.Encoder();
      const base32String = encoder.write(buf1).finalize();
      let buf2 = EncodeTools.base32ToNodeBuffer(base32String);

      assert.isTrue(Buffer.isBuffer(buf2));

      assert.isTrue(
        buf1.equals(buf2),
        'Buffers were not equal'
      );
    });
  });

  describe('nodeBufferToBase32url', async function () {
    it('should return data from its base32 representation', async function () {
      let buf1 = Buffer.from(chance.string());

      const encoder = new base32.Encoder();
      const str1 = encoder.write(buf1).finalize();
      let str2 = EncodeTools.nodeBufferToBase32(buf1);

      assert.equal(
        str2,
        str1,
        'Base64URL strings were not equal'
      );
    });
  });

  for (let hashWasamAlgo of [
    'crc32',
    'xxhash32',
    'xxhash64',
    'sha1',
    'sha512',
    'sha3',
    'md5'
  ]) {
    describe(hashWasamAlgo, async function () {
      it('should return a '+hashWasamAlgo+' hash of data', async function (){
        let buf = randomBuffer();

        let [ hash1, hash2 ] = await Promise.all([
          // @ts-ignore
          hashWasm[hashWasamAlgo](buf),
          // @ts-ignore
          EncodeTools[hashWasamAlgo](buf)
        ]);

        assert.equal(hash2.toString('hex'), hash1, 'Hashes were not the same');
      });
    });
  }

  describe('sha2', async function () {
    it('should return a sha2 hash of data', async function (){
      let buf = randomBuffer();

      let [ hash1, hash2 ] = await Promise.all([
        // @ts-ignore
        hashWasm.sha512(buf),
        // @ts-ignore
        EncodeTools.sha2(buf)
      ]);

      assert.equal(hash2.toString('hex'), hash1, 'Hashes were not the same');
    });
  });

  describe('bcrypt', async function () {
    it('should return bcrypt data in the proper format', async function (){
      let password = chance.string();
      let options: BcryptOptions = {
        password: null,
        salt: randomBuffer({ min: 16, max: 16 }),
        outputType: 'encoded',
        costFactor: null
      };

      let hash1 = (await EncodeTools.bcrypt(Buffer.from(password), options)).toString('utf8');
      let hash2 = await hashWasm.bcrypt({
        ...options,
        costFactor: 11,
        password
      });


      assert.equal(hash1, hash2, 'Hashes were not the same');
    });
    it('should bcrypt data and it should be able to verify password', async function (){
      let password = chance.string();
      let options: BcryptOptions = {
        password: null,
        salt: randomBuffer({ min: 16, max: 16 }),
        outputType: 'encoded',
        costFactor: null
      };

      let hash = (await EncodeTools.bcrypt(Buffer.from(password), options)).toString('utf8');
      assert.isTrue(await hashWasm.bcryptVerify({
        hash,
        password: password
      }), 'Password and hash did not match');
    });
  });

  describe('bcryptVerify', async function () {
    it('should verify bcrypt data', async function (){
      let password =  chance.string();
      let options: BcryptOptions = {
        password,
        salt: randomBuffer({ min: 16, max: 16 }),
        outputType: 'encoded',
        costFactor: 11
      };

      let hash = (await hashWasm.bcrypt(options));
      assert.isTrue(await EncodeTools.bcryptVerify(password, hash), 'Password and hash did not match');
    });
  });

  describe('hash/bcrypt', async function () {
    it('should return bcrypt data in the proper format', async function (){
      let password = chance.string();
      let options: BcryptOptions = {
        password: null,
        salt: randomBuffer({ min: 16, max: 16 }),
        outputType: 'encoded',
        costFactor: null
      };

      let enc = new EncodeTools();
      let hash1 = (await enc.hash(
        Buffer.from(password, 'utf8'),
        HashAlgorithm.bcrypt,
        options
      )).toString('utf8');

      let hash2 = await hashWasm.bcrypt({
        ...options,
        costFactor: 11,
        password
      });

      assert.equal(hash1, hash2, 'Hashes were not the same');
    });
    it('should bcrypt data and it should be able to verify password', async function (){
      let password = chance.string();
      let options: BcryptOptions = {
        password: null,
        salt: randomBuffer({ min: 16, max: 16 }),
        outputType: 'encoded',
        costFactor: null
      };

      let enc = new EncodeTools();
      let hash = (await enc.hash(
        Buffer.from(password, 'utf8'),
        HashAlgorithm.bcrypt,
        options
      )).toString('utf8');


      assert.isTrue(await hashWasm.bcryptVerify({
        hash,
        password: password
      }), 'Password and hash did not match');
    });
  });

  //
  // describe('hashString', async function () {
  //   for (let [ algo, pair ] of Array.from(hashInputPairs.entries())) {
  //     it(`should hash a string using the ${algo} algorithm`, async function () {
  //       let str = chance.string();
  //       let enc = new EncodeTools();
  //       let [hash1,hash2] = await Promise.all([
  //         enc.hashString(str, algo),
  //         pair.toBuffer(str)
  //       ]);
  //
  //       assert.deepEqual(Buffer.from(hash1), hash2, 'Hashes returned were not the same ')
  //     });
  //   }
  // });
  //

  describe('uuidv1Array', async function () {
    it('should return array of 16 numbers', async function () {
      assert.lengthOf((EncodeTools as any).uuidv1Array(), 16, 'Array returned was wrong size')
    });

    it('uuids created in the future should be larger than ones created before', async function () {
      let uuid1 = (EncodeTools as any).uuidv1Array();
      let uuid2 = (EncodeTools as any).uuidv1Array();

      let num1  = parseInt(Buffer.from(uuid1).toString('hex'), 16);
      let num2  = parseInt(Buffer.from(uuid2).toString('hex'), 16);
      assert.isAbove(num2, num1, 'Second uuid created was not larger than the first');
    });
  });

  describe('uuidv4Array', async function () {
    it('should return array of 16 numbers', async function () {
      assert.lengthOf((EncodeTools as any).uuidv4Array(), 16, 'Array returned was wrong size')
    });
  });

  describe('nanoid', async function () {
    it('should array of 21 symbols by default', async function () {
      let id = EncodeTools.nanoid();
      assert.lengthOf(id, 21, 'nanoid was not 21 characters');
    });

    it('should array of a variable size if given', async function () {
      let size = chance.integer({ min: 0, max: 1e6 });
      let id = EncodeTools.nanoid(size);
      assert.lengthOf(id, size, `nanoid wasn't ${size} characters`);
    });
  });


  describe('uniqueId/nanoid', async function () {
    it('should array of 21 symbols by default', async function () {
      let enc = new EncodeTools();
      let id = enc.uniqueId(IDFormat.nanoid) as string;
      assert.lengthOf(id, 21, 'nanoid was not 21 characters');
    });

    it('should array of a variable size if given', async function () {
      let enc = new EncodeTools();
      let size = chance.integer({ min: 0, max: 1e6 });
      let id = enc.uniqueId(IDFormat.nanoid, size) as string;
      assert.lengthOf(id, size, `nanoid wasn't ${size} characters`);
    });
  });


  describe('timestamp', async function () {
    it('timestamps created in the future should be larger than ones created before', async function () {
      let num1 = EncodeTools.timestamp();

      await new Promise<void>((resolve) => setTimeout(() => { resolve(); }, 4));

      let num2 = EncodeTools.timestamp();

      assert.isAbove(num2, num1, 'Second timestamp created was not larger than the first');
    });
  });

  describe('unqiueId/timestamp', async function () {
    it('timestamps created in the future should be larger than ones created before', async function () {
      let enc = new EncodeTools();
      let num1 = enc.uniqueId(IDFormat.timestamp) as number;

      await new Promise<void>((resolve) => setTimeout(() => { resolve(); }, 4));

      let num2 = enc.uniqueId(IDFormat.timestamp) as number;

      assert.isAbove(num2, num1, 'Second timestamp created was not larger than the first');
    });
  });

  describe('uuidv1', async function () {
    it('should return a Buffer of 16 bytes', async function () {
      let buf = EncodeTools.uuidv1();

      assert.isTrue(Buffer.isBuffer(buf));

      assert.equal(buf.byteLength, 16, 'Buffer returned was wrong size');
    });

    it('uuids created in the future should be larger than ones created before', async function () {
      let uuid1 = (EncodeTools).uuidv1();
      let uuid2 = (EncodeTools).uuidv1();

      assert.isTrue(Buffer.isBuffer(uuid1));
      assert.isTrue(Buffer.isBuffer(uuid2));

      let num1 = parseInt((uuid1).toString('hex'), 16);
      let num2 = parseInt((uuid2).toString('hex'), 16);
      assert.isAbove(num2, num1, 'Second uuid created was not larger than the first');
    });
  });

  describe('uniqueId/uuidv1', async function () {
    it('should return a Buffer of 16 bytes', async function () {
      let enc = new EncodeTools();
      let buf = enc.uniqueId(IDFormat.uuidv1) as Buffer;

      assert.isTrue(Buffer.isBuffer(buf));

      assert.equal(buf.byteLength, 16, 'Buffer returned was wrong size');
    });

    it('uuids created in the future should be larger than ones created before', async function () {
      let enc = new EncodeTools();
      let uuid1 = enc.uniqueId(IDFormat.uuidv1) as Buffer;
      let uuid2 = enc.uniqueId(IDFormat.uuidv1) as Buffer;

      assert.isTrue(Buffer.isBuffer(uuid1));
      assert.isTrue(Buffer.isBuffer(uuid2));

      let num1 = parseInt((uuid1).toString('hex'), 16);
      let num2 = parseInt((uuid2).toString('hex'), 16);
      assert.isAbove(num2, num1, 'Second uuid created was not larger than the first');
    });
  });

  describe('uniqueId/uuidv4', async function () {
    it('should return a Buffer of 16 bytes', async function () {
      let enc = new EncodeTools();
      let buf = enc.uniqueId(IDFormat.uuidv4) as Buffer;

      assert.isTrue(Buffer.isBuffer(buf));

      assert.equal(buf.byteLength, 16, 'Buffer returned was wrong size');
    });
  });

  describe('unqiueId/uuidv4string', async function () {
    it('should return a uuid in the standard uuid format', async function () {
      let enc = new EncodeTools();
      let str = enc.uniqueId(IDFormat.uuidv4String) as string;

      assert.match(str, /\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b/, 'string returned was not a uuid');
    });
  });

  describe('encodeSlugID', async function () {
    it('should return a uuid in the slugid uuid format', async function () {
      let uuid = chance.bool() ? EncodeTools.uuidv1() : EncodeTools.uuidv4();
      let str = EncodeTools.encodeSlugID(uuid);

      assert.match(str, /[A-Za-z0-9_-]{22}/, 'string returned was not a slugid uuid');
    });

    it('should be able to decode uuid in the slugid format', async function () {
      let uuid = chance.bool() ? EncodeTools.uuidv1() : EncodeTools.uuidv4();
      let str = EncodeTools.encodeSlugID(uuid);

      let uuid2 = UUIDParse(slugid.decode(str))

      assert.deepEqual(uuid2, uuid, 'decoded UUID did not match the original');
    });
  });

  describe('decodeSlugID', async function () {
    it('should return a uuid from the slugid uuid format', async function () {
      let uuid = chance.bool() ? EncodeTools.uuidv1() : EncodeTools.uuidv4();
      let str = slugid.encode(UUIDStringify( uuid ));

      let uuid2 = EncodeTools.decodeSlugID(str);

      assert.deepEqual(uuid2, uuid, 'decoded UUID did not match the original');
    });
  });

  describe('newObjectId', async function () {
    it('should return a objectId as a buffer', async function () {
      let objectId = EncodeTools.newObjectId();
      let f = () => { new (require('bson').ObjectId)(objectId) }
      assert.doesNotThrow(f);
    });

    it('objectIds created in the future should be larger than ones created before', async function () {
      let objectId1 = EncodeTools.newObjectId();
      await new Promise<void>((resolve) => setTimeout(() => { resolve(); }, 1e3));
      let objectId2 = EncodeTools.newObjectId();

      let num1 = parseInt((objectId1).toString('hex'), 16);
      let num2 = parseInt((objectId2).toString('hex'), 16);
      assert.isAbove(num2, num1, 'Second uuid created was not larger than the first');
    });
  });

  describe('uniqueId/objectId', async function () {
    it('should return a objectId as a buffer', async function () {
      let enc = new EncodeTools();
      let objectId = enc.uniqueId(IDFormat.objectId) as Buffer;
      let f = () => { new (require('bson').ObjectId)(objectId) }
      assert.doesNotThrow(f);
    });

    it('objectIds created in the future should be larger than ones created before', async function () {
      let enc = new EncodeTools();
      let objectId1 = enc.uniqueId(IDFormat.objectId) as Buffer;
      await new Promise<void>((resolve) => setTimeout(() => { resolve(); }, 1e3));
      let objectId2 = enc.uniqueId(IDFormat.objectId) as Buffer;

      let num1 = parseInt((objectId1).toString('hex'), 16);
      let num2 = parseInt((objectId2).toString('hex'), 16);
      assert.isAbove(num2, num1, 'Second uuid created was not larger than the first');
    });
  });

  describe('objectToJson', async function () {
    it('should convert object to json', async function () {
      let obj = randomObject();
      let str1 = JSON.stringify(obj);
      let str2 = EncodeTools.objectToJson<unknown>(obj);

      assert.equal(str2, str1, 'json text of the object is not the same');
    });
  });

  describe('jsonToObject', async function () {
    it('should convert json to object', async function () {
      let obj = randomObject();
      let str1 = JSON.stringify(obj);
      let obj2 = EncodeTools.jsonToObject<unknown>(str1);

      assert.deepEqual(obj2, obj, 'object from json text is not the same');
    });
  });

  describe('objectToMsgpack', async function () {
    it('should convert object to json', async function () {
      let obj = randomObject();
      let buf1 = msgpack.encode(obj);
      let buf2 = EncodeTools.objectToMsgpack<unknown>(obj);

      assert.deepEqual(buf2, buf1, 'msgpack buffer of the object is not the same');
    });
  });

  describe('msgpackToObject', async function () {
    it('should convert msgpack to object', async function () {
      let obj = randomObject();
      let buf1 = msgpack.encode(obj);
      let obj2 = EncodeTools.msgpackToObject<unknown>(Buffer.from(buf1));

      assert.deepEqual(obj2, obj, 'object from msgpack buffer is not the same');
    });
  });

  describe('objectToCbor', async function () {
    it('should convert object to cbor', async function () {
      let obj = randomObject();
      let buf1 = cborX.encode(obj);
      let buf2 = EncodeTools.objectToCbor<unknown>(obj);

      assert.deepEqual(buf2, buf1, 'cbor buffer of the object is not the same');
    });
  });

  describe('cborToObject', async function () {
    it('should convert cbor to object', async function () {
      let obj = randomObject();
      let buf1 = cborX.encode(obj);
      let obj2 = EncodeTools.cborToObject<unknown>(Buffer.from(buf1));

      assert.deepEqual(obj2, obj, 'object from cbor buffer is not the same');
    });
  });


  describe('objectToBson', async function () {
    it('should convert object to bson', async function () {
      let obj = randomObject();
      let buf1 = BSONSerialize(obj);
      let buf2 = EncodeTools.objectToBson<unknown>(obj);

      assert.deepEqual(buf2, buf1, 'bson buffer of the object is not the same');
    });
  });

  describe('bsonToObject', async function () {
    it('should convert bson to object', async function () {
      let obj = randomObject();
      let buf1 = BSONSerialize(obj);
      let obj2 = EncodeTools.bsonToObject<unknown>(buf1);

      assert.deepEqual(obj2, obj, 'object from bson buffer is not the same');
    });
  });

  describe('decompressLzma', async function () {
    this.timeout(60e3);
    it('should compress buffer as lzma', async function () {
      let inBuf = randomBuffer();
      let lzma = new LZMA();
      let buf1 = Buffer.from(await new Promise<Buffer>((resolve, reject) => {
        lzma.compress(inBuf, chance.integer({ min: 1, max: 9 }),(result: any, error: any) => {
          if (error) reject(error);
          else resolve(result);
        });
      }));

      let buf2 = await EncodeTools.decompressLZMA(buf1);

      assert.isTrue(Buffer.isBuffer(buf2), 'LZMA did not return a buffer');
      assert.deepEqual(buf2, inBuf, 'Buffers are not the same');
    });
  });

  describe('compressLzma', async function () {
    this.timeout(60e3);
    it('should compress buffer as lzma', async function () {
      let inBuf = randomBuffer();
      let lzma = new LZMA();
      let buf1 = await EncodeTools.compressLZMA(inBuf, chance.integer({ min: 1, max: 9 }))
      let buf2 = Buffer.from(await new Promise<Buffer>((resolve, reject) => {
        lzma.decompress(buf1, (result: any, error: any) => {
          if (error) reject(error);
          else resolve(result);
        });
      }));

      assert.isTrue(Buffer.isBuffer(buf2), 'LZMA did not return a buffer');
      assert.deepEqual(buf2, inBuf, 'Buffers are not the same');
    });
  });

  describe('decompressZstd', async function () {
    this.timeout(60e3);
    it('should compress buffer as lzma', async function () {
      let inBuf = randomBuffer();
      let buf1 = Buffer.from(await new Promise<Buffer>((resolve, reject) => {
        ZstdCodec.run((zstd: any) => {
          const simple = new zstd.Simple();
          try {
            const data = simple.compress(inBuf, chance.integer({ min: 1, max: 9 }));
            resolve(data);
          } catch (err) {
            reject(err);
          }
        });
      }));

      let buf2 = await EncodeTools.decompressZStd(buf1);

      assert.isTrue(Buffer.isBuffer(buf2), 'ZStd did not return a buffer');
      assert.deepEqual(buf2, inBuf, 'Buffers are not the same');
    });
  });


  describe('compressZstd', async function () {
    this.timeout(60e3);
    it('should compress buffer as lzma', async function () {
      let inBuf = randomBuffer();
      let buf1 = await EncodeTools.compressZStd(inBuf, chance.integer({ min: 1, max: 9 }))
      let buf2 = Buffer.from(await new Promise<Buffer>((resolve, reject) => {
        ZstdCodec.run((zstd: any) => {
          const simple = new zstd.Simple();
          try {
            const data = simple.decompress(buf1);
            resolve(data);
          } catch (err) {
            reject(err);
          }
        });
      }));

      assert.isTrue(Buffer.isBuffer(buf2), 'ZStd did not return a buffer');
      assert.deepEqual(buf2, inBuf, 'Buffers are not the same');
    });
  });



  describe('get WithDefaults', async function () {
    it('encode tools options should have the default options', async function () {
      let enc = EncodeTools.WithDefaults;
      assert.deepEqual(enc.options, DEFAULT_ENCODE_TOOLS_OPTIONS, 'Options are not the default options');
    });
  });
  describe('create', async function () {
    it('encode tools options should have the random options', async function () {
      let opts = randomOptions();
      let enc = new EncodeTools(opts);
      assert.deepEqual(enc.options, opts, 'Options are not the default options');
    });
  });

  describe('getImageMetadata', async function () {
    it('create an image an get the metadata for that image', async function () {
      let dims = {
        width: chance.integer({ min: 1, max: 1e3}),
        height: chance.integer({ min: 1, max: 1e3}),
        format: chance.shuffle([ ImageFormat.png, ImageFormat.jpeg ])[0]
      }

      let image = await (await new Promise<any>((resolve, reject) => {
        new (Jimp)(dims.width, dims.height, ImageRunnerBase.getRandomColor(), (err: unknown, image: any) => {
          if (err) reject(err);
          else resolve(image);
        });
      })).getBufferAsync('image/'+dims.format);

      let obj2 = await EncodeTools.getImageMetadata(image);

      assert.deepEqual(obj2, dims, 'Image metadata is not the same as the image that was create');
    });
  });

  for (let test of tests) {
    await test.testEncode();

    if (test.hasDecode) {
      await test.testDecode();
    }
  }

});
