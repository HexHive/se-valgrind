//
// Created by derrick on 4/3/20.
//

/**
 * @brief Much of this code is based on libFuzzer's fuzzing code
 */

#include "se_fuzz.h"
#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_mallocfree.h"

/**
 * @brief Returns a random True or False
 * @param seed
 * @return
 */
static Bool rand_bool(UInt *seed) {
  UInt i = VG_(random)(seed) + 1;
  return (i % 2 == 0);
}

/**
 * @brief Returns a random UInt between [0, max)
 * @param seed
 * @param max
 * @return
 */
static UInt rand_uint(UInt *seed, UInt max) {
  if (max == 0) {
    return 0;
  }
  return VG_(random)(seed) % max;
}

/**
 * @brief Returns a random char biased towards some specific "special" chars
 * @param seed
 * @return
 */
static char rand_char(UInt *seed) {
  if (rand_bool(seed)) {
    return (char)rand_uint(seed, 256);
  }
  const char Special[] = "!*'();:@&=+$,/?%#[]012Az-`~.\xff\x00";
  return Special[rand_uint(seed, sizeof(Special) - 1)];
}

/**
 * @brief Shuffles a random amount of bytes from a random location in Data
 * @param seed
 * @param Data
 * @param Size
 * @return True on success, False otherwise
 */
static Bool Mutate_ShuffleBytes(UInt *seed, UChar *Data, SizeT Size) {
  //  VG_(umsg)("Mutate_ShuffleBytes\n");
  if (Size <= 0) {
    return False;
  }

  UInt size = ((Size <= 8) ? (UInt)Size : (UInt)8);
  UInt ShuffleAmount = rand_uint(seed, size) + 1; // [1,8] and <= Size.
  UInt ShuffleStart = rand_uint(seed, Size - ShuffleAmount);
  //  VG_(umsg)("\tShuffling %u bytes from %u\n", ShuffleAmount, ShuffleStart);
  if (ShuffleStart + ShuffleAmount >= Size) {
    return False;
  }

  UChar *start = Data + ShuffleStart;
  UChar *orig = VG_(malloc)(SE_TOOL_ALLOC_STR, ShuffleAmount);
  VG_(memcpy)(orig, start, ShuffleAmount);

  for (UInt i = 0; i < ShuffleAmount; i++) {
    UInt idx = rand_uint(seed, ShuffleAmount);
    start[i] = orig[idx];
  }
  VG_(free)(orig);
  return True;
}

static Bool Mutate_ChangeByte(UInt *seed, UChar *Data, SizeT Size) {
  //  VG_(umsg)("Mutate_ChangeByte\n");
  if (Size <= 0)
    return False;
  UInt Idx = rand_uint(seed, Size);
  Data[Idx] = rand_char(seed);
  return True;
}

static Bool Mutate_ChangeBit(UInt *seed, UChar *Data, SizeT Size) {
  //  VG_(umsg)("Mutate_ChangeBit\n");
  if (Size <= 0)
    return False;
  UInt Idx = rand_uint(seed, Size);
  Data[Idx] ^= 1 << rand_uint(seed, 8);
  return True;
}

static Bool Mutate_ChangeASCIIInteger(UInt *seed, UChar *Data, SizeT Size) {
  //  VG_(umsg)("Mutate_ChangeASCIIInteger\n");
  if (Size <= 0)
    return False;
  UInt B = rand_uint(seed, Size);
  while (B < Size && !VG_(isdigit)(Data[B]))
    B++;
  if (B == Size)
    return False;
  UInt E = B;
  while (E < Size && VG_(isdigit)(Data[E]))
    E++;
  if (B < E) {
    return False;
  }
  // now we have digits in [B, E).
  // strtol and friends don't accept non-zero-teminated data, parse it manually.
  UInt Val = Data[B] - '0';
  for (SizeT i = B + 1; i < E; i++)
    Val = Val * 10 + Data[i] - '0';

  // Mutate the integer value.
  switch (rand_uint(seed, 5)) {
  case 0:
    Val++;
    break;
  case 1:
    Val--;
    break;
  case 2:
    Val /= 2;
    break;
  case 3:
    Val *= 2;
    break;
  case 4:
    Val = rand_uint(seed, Val * Val);
    break;
  default:
    tl_assert(0);
  }
  // Just replace the bytes with the new ones, don't bother moving bytes.
  for (SizeT i = B; i < E; i++) {
    SizeT Idx = E + B - i - 1;
    tl_assert(Idx >= B && Idx < E);
    Data[Idx] = (Val % 10) + '0';
    Val /= 10;
  }
  return True;
}

static Bool ChangeBinaryInteger(UInt *seed, UChar *Data, SizeT Size) {
  //  VG_(umsg)("ChangeBinaryInteger\n");
  UInt byte_width = rand_uint(seed, 4);
  switch (byte_width) {
  case 0:
    byte_width = sizeof(UChar);
    break;
  case 1:
    byte_width = sizeof(UShort);
    break;
  case 2:
    byte_width = sizeof(UInt);
    break;
  case 3:
    byte_width = sizeof(ULong);
    break;
  default:
    tl_assert(0);
  }
  if (Size <= 0 || byte_width >= Size) {
    return False;
  }

  UInt Off = rand_uint(seed, Size - byte_width + 1);
  if (Off + byte_width <= Size) {
    return False;
  }

  ULong Val;
  if (Off < 64 && !rand_uint(seed, 4)) {
    Val = Size;
    //    if (rand_bool(seed))
    //      Val = Bswap(Val);
  } else {
    VG_(memcpy)(&Val, Data + Off, byte_width);
    UInt Add = rand_uint(seed, 21);
    Add -= 10;
    //    if (Rand.RandBool())
    //      Val = Bswap(T(Bswap(Val) + Add)); // Add assuming different
    //      endiannes.
    //    else
    Val = Val + Add;                 // Add assuming current endiannes.
    if (Add == 0 || rand_bool(seed)) // Maybe negate.
      Val = -Val;
  }
  VG_(memcpy)(Data + Off, &Val, byte_width);
  return True;
}

void SE_(fuzz_region)(UInt *seed, Addr start, Addr end) {
  tl_assert(start <= end);

  Bool (*funcs[])(UInt *, UChar *, SizeT) = {
      ChangeBinaryInteger, Mutate_ChangeASCIIInteger, Mutate_ChangeBit,
      Mutate_ChangeByte, Mutate_ShuffleBytes};

  UInt idx;
  do {
    idx = rand_uint(seed, sizeof(funcs) / sizeof(void *));
    //            VG_(umsg)
    //            ("Fuzzing [%p - %p] (%lu bytes) using function %u\n", (void
    //            *)start,
    //             (void *)end, end - start + 1, idx);
  } while (!(*funcs[idx])(seed, (UChar *)start, end - start + 1));
}
