"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Same crafted archive as craftBomb(), but carrying the real crc-32 of `content`,
// so a reader whose allocation is bound by the real data returns the payload.
function craftBombWithCrc(declaredSize, method, content, crc) {
    const zip = craftBomb(declaredSize, method, content);
    const lfhLength = Utils.Constants.LOCHDR + 1 + content.length; // header + name ("a") + payload
    zip.writeUInt32LE(crc >>> 0, Utils.Constants.LOCCRC); // local header crc-32
    zip.writeUInt32LE(crc >>> 0, lfhLength + Utils.Constants.CENCRC); // central header crc-32
    return zip;
}

// Lazily zeroed pages mean RSS alone does not always reveal a huge Buffer.alloc,
// so also watch the requested size itself: fail fast (without committing any
// memory) if anything asks Buffer.alloc for more than ALLOC_LIMIT bytes while
// `fn` runs. Returns the largest size requested.
const ALLOC_LIMIT = 64 * 1024 * 1024;
function withAllocGuard(fn) {
    const originalAlloc = Buffer.alloc;
    let largest = 0;
    Buffer.alloc = function (size) {
        if (size > largest) largest = size;
        if (size > ALLOC_LIMIT) {
            throw new Error("unbounded Buffer.alloc of " + size + " bytes");
        }
        return originalAlloc.apply(Buffer, arguments);
    };
    try {
        fn();
    } finally {
        Buffer.alloc = originalAlloc;
    }
    return largest;
}

describe("decompression bomb (declared size) - CVE-2026-39244 - allocation size", () => {
    // the ~4 GB uncompressed size from the original proof of concept
    const DECLARED = 0xffffffff;
    const STORED = Utils.Constants.STORED;
    const DEFLATED = Utils.Constants.DEFLATED;

    it("never requests the declared size for a crc-invalid STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, STORED, Buffer.from("A")));
        const entry = zip.getEntries()[0];
        const largest = withAllocGuard(() => {
            expect(() => entry.getData()).to.throw(/CRC32/);
        });
        expect(largest).to.be.below(ALLOC_LIMIT);
    });

    it("never requests the declared size for a bogus DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, DEFLATED, Buffer.from([0x00])));
        const entry = zip.getEntries()[0];
        const largest = withAllocGuard(() => {
            expect(() => entry.getData()).to.throw();
        });
        expect(largest).to.be.below(ALLOC_LIMIT);
    });

    it("returns only the real bytes of a STORED entry that lies about its size", () => {
        const content = Buffer.from("A");
        const zip = new Zip(craftBombWithCrc(DECLARED, STORED, content, Utils.crc32(content)));
        let data;
        const largest = withAllocGuard(() => {
            data = zip.getEntries()[0].getData();
        });
        expect(largest).to.be.below(ALLOC_LIMIT);
        expect(data.equals(content)).to.equal(true);
    });

    it("returns only the inflated bytes of a DEFLATED entry that lies about its size", () => {
        const payload = Buffer.from("tiny payload, huge declared size");
        const zip = new Zip(craftBombWithCrc(DECLARED, DEFLATED, zlib.deflateRawSync(payload), Utils.crc32(payload)));
        let data;
        const largest = withAllocGuard(() => {
            data = zip.getEntries()[0].getData();
        });
        expect(largest).to.be.below(ALLOC_LIMIT);
        expect(data.equals(payload)).to.equal(true);
    });

    it("does not allocate the declared size through readFile() and readAsText()", () => {
        const payload = Buffer.from("readable text");
        const zip = new Zip(craftBombWithCrc(DECLARED, DEFLATED, zlib.deflateRawSync(payload), Utils.crc32(payload)));
        let file, text;
        const largest = withAllocGuard(() => {
            file = zip.readFile("a");
            text = zip.readAsText("a");
        });
        expect(largest).to.be.below(ALLOC_LIMIT);
        expect(file.equals(payload)).to.equal(true);
        expect(text).to.equal(payload.toString());
    });

    it("does not allocate the declared size when reading a STORED entry asynchronously", (done) => {
        const content = Buffer.from("A");
        const zip = new Zip(craftBombWithCrc(DECLARED, STORED, content, Utils.crc32(content)));
        const largest = withAllocGuard(() => {
            zip.getEntries()[0].getDataAsync((data, err) => {
                try {
                    expect(err).to.equal(undefined);
                    expect(data.equals(content)).to.equal(true);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });
        expect(largest).to.be.below(ALLOC_LIMIT);
    });

    it("does not allocate the declared size when reading a DEFLATED entry asynchronously", (done) => {
        const payload = Buffer.from("tiny async payload, huge declared size");
        const zip = new Zip(craftBombWithCrc(DECLARED, DEFLATED, zlib.deflateRawSync(payload), Utils.crc32(payload)));
        const largest = withAllocGuard(() => {
            zip.getEntries()[0].getDataAsync((data, err) => {
                try {
                    expect(err).to.equal(undefined);
                    expect(data.equals(payload)).to.equal(true);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });
        expect(largest).to.be.below(ALLOC_LIMIT);
    });
});
