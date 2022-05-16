Array when initiated with `new Array` are inlined.

```js
var oob_Array=new Array(1)
oob_Array[0]=0x41414141
var uint32_Array=new Uint32Array(0x1000)
for(var i=0; i<0x1000; i=i+1) {uint32_Array[i]=0x4141414141}
```

oob_Array and uint32_Array will be inligned.
Not inligned when initiated with `var a = [0x41414141]` (Don't know why.)

When on browser do the Date.now thing to leak libxul.so -> memmove -> libc_base
overwrite memmove to system

```Cpp

enum JSValueType : uint8_t
{
    JSVAL_TYPE_DOUBLE              = 0x00,
    JSVAL_TYPE_INT32               = 0x01,
    JSVAL_TYPE_BOOLEAN             = 0x02,
    JSVAL_TYPE_UNDEFINED           = 0x03,
    JSVAL_TYPE_NULL                = 0x04,
    JSVAL_TYPE_MAGIC               = 0x05,
    JSVAL_TYPE_STRING              = 0x06,
    JSVAL_TYPE_SYMBOL              = 0x07,
    JSVAL_TYPE_PRIVATE_GCTHING     = 0x08,
    JSVAL_TYPE_OBJECT              = 0x0c,

    /* These never appear in a jsval; they are only provided as an out-of-band value. */
    JSVAL_TYPE_UNKNOWN             = 0x20,
    JSVAL_TYPE_MISSING             = 0x21
};

----

JS_ENUM_HEADER(JSValueTag, uint32_t)
{
    JSVAL_TAG_MAX_DOUBLE           = 0x1FFF0,
    JSVAL_TAG_INT32                = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_INT32,
    JSVAL_TAG_UNDEFINED            = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_UNDEFINED,
    JSVAL_TAG_NULL                 = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_NULL,
    JSVAL_TAG_BOOLEAN              = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_BOOLEAN,
    JSVAL_TAG_MAGIC                = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_MAGIC,
    JSVAL_TAG_STRING               = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_STRING,
    JSVAL_TAG_SYMBOL               = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_SYMBOL,
    JSVAL_TAG_PRIVATE_GCTHING      = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_PRIVATE_GCTHING,
    JSVAL_TAG_OBJECT               = JSVAL_TAG_MAX_DOUBLE | JSVAL_TYPE_OBJECT
} JS_ENUM_FOOTER(JSValueTag);

----

enum JSValueShiftedTag : uint64_t
{
    JSVAL_SHIFTED_TAG_MAX_DOUBLE      = ((((uint64_t)JSVAL_TAG_MAX_DOUBLE)     << JSVAL_TAG_SHIFT) | 0xFFFFFFFF),
    JSVAL_SHIFTED_TAG_INT32           = (((uint64_t)JSVAL_TAG_INT32)           << JSVAL_TAG_SHIFT),
    JSVAL_SHIFTED_TAG_UNDEFINED       = (((uint64_t)JSVAL_TAG_UNDEFINED)       << JSVAL_TAG_SHIFT),
    JSVAL_SHIFTED_TAG_NULL            = (((uint64_t)JSVAL_TAG_NULL)            << JSVAL_TAG_SHIFT),
    JSVAL_SHIFTED_TAG_BOOLEAN         = (((uint64_t)JSVAL_TAG_BOOLEAN)         << JSVAL_TAG_SHIFT),
    JSVAL_SHIFTED_TAG_MAGIC           = (((uint64_t)JSVAL_TAG_MAGIC)           << JSVAL_TAG_SHIFT),
    JSVAL_SHIFTED_TAG_STRING          = (((uint64_t)JSVAL_TAG_STRING)          << JSVAL_TAG_SHIFT),
    JSVAL_SHIFTED_TAG_SYMBOL          = (((uint64_t)JSVAL_TAG_SYMBOL)          << JSVAL_TAG_SHIFT),
    JSVAL_SHIFTED_TAG_PRIVATE_GCTHING = (((uint64_t)JSVAL_TAG_PRIVATE_GCTHING) << JSVAL_TAG_SHIFT),
    JSVAL_SHIFTED_TAG_OBJECT          = (((uint64_t)JSVAL_TAG_OBJECT)          << JSVAL_TAG_SHIFT)
};

```


```cpp
class NativeObject
{
    js::GCPtrObjectGroup group_;
    void* shapeOrExpando_;
    js::HeapSlot *slots_;
    js::HeapSlot *elements_;
};


```
