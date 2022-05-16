---

title: Meet-5 -> Basic Browser Exploitation
author: th3f0x
styles:
  style: gruvbox-dark

---

## Overview

- [Overview](#overview)
- [JS Objects in Firefox](#js-objects-in-firefox)
- [Challenges](#challenges)
- [Misc Tips](#misc-tips)
- [Home Assignment](#home-assignment)
- [Links](#links)

---

## JS Objects in Firefox

```cpp
class NativeObject : public JSObject
    {
        /*
         * From JSObject; structural description to avoid dictionary
         * lookups from property names to slots_ array indexes.
         */
        js::HeapPtrShape shape_;

        /*
         * From JSObject; the jsobject's type (unrelated to the jsval
         * type I described above).
         */
        js::HeapPtrTypeObject type_;

        /*
         * From NativeObject; pointer to the jsobject's properties'
         * storage.
         */
        js::HeapSlot *slots_;

        /*
         * From NativeObject; pointer to the jsobject's elements' storage.
         * This is used by JavaScript arrays and typed arrays. The
         * elements of JavaScript arrays are jsvals as I described them
         * above.
         */
        js::HeapSlot *elements_;

        /*
         * From ObjectElements; how are data written to elements_ and
         * other metadata.
         */
        uint32_t flags;

        /*
         * From ObjectElements; number of initialized elements, less or
         * equal to the capacity (see below) for non-array jsobjects, and
         * less or equal to the length (see below) for array jsobjects.
         */
        uint32_t initializedLength;

        /*
         * From ObjectElements; number of allocated slots (for object
         * properties).
         */
        uint32_t capacity;

        /*
         * From ObjectElements; the length of array jsobjects.
         */
        uint32_t length;
    };
```

The ability to change the `elements` or `slots` value in this structure can read to arbitrary read/write primitives.

---

## Challenges

- Blazefox (from Blaze CTF 2018)
  - Files:
    - `https://s3.us-east-2.amazonaws.com/blazefox/blazefox/blaze_firefox_small.tar.gz`
    - `https://s3.us-east-2.amazonaws.com/blazefox/blazefox/blaze_firefox_dist_large.tar.gz`

- hfs\_browser (from  Midnight Sun CTF 2022 Quals)
  - Files: `hfs_browser.tgz`

---

## Misc Tips

- Building just the js shell (for firefox):

```sh
patch -p1 < <patch file location>
cd js/src/
cp configure.in configure && autoconf2.13
mkdir build_DBG.OBJ
cd build_DBG.OBJ
../configure --enable-debug --disable-optimize
make # or make -j8
cd ..
```

- SpiderMonkey Exploitation Strategy:
  - Leak base of `libxul.so`(contains most of the browser code). This can be done by leaking address of native function like `Date.now()`. This can be leaked by setting this function as a property of the array. After some short chain of pointers, the address will be leaked.
  - Get the GOT address for `memmove` in `libxul.so` (using previous base address). Then leak the value, to get the address of `memmove`.
  - Calculate the base address of libc from the previously obtained `memmove` address. Then use this base address to get the address of `system` function.
  - Then overwrite the GOT entry for `memmove` to `system`.
  - Once all this is done, move the target command into a `Uint8Array`, with null termination. Then call the `copyWithin` function to trigger the command.
  - A sample exploit for the blazefox challenge solved using this technique is also provided [here](blazefox_exploit.js).


---

## Home Assignment

- Try to read some portions from the [links](#links)
- Try both challenges yourself

---

## Links

- [SpiderMonkey Internal](http://www.phrack.org/issues/69/14.html)
- [Intro to SpiderMonkey Exploitation](https://doar-e.github.io/blog/2018/11/19/introduction-to-spidermonkey-exploitation/)
- [Achieving Code Execution](https://phoenhex.re/2017-06-21/firefox-structuredclone-refleak#achieving-arbitrary-code-execution)
- [LiveOverflow Browser Exploitation series](https://www.youtube.com/playlist?list=PLhixgUqwRTjwufDsT1ntgOY9yjZgg5H_t)
