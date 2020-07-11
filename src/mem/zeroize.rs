use core::ptr;
use core::sync::atomic;
use core::slice::IterMut;


// NOTE: 代码来源自 https://docs.rs/zeroize


pub trait Zeroize {
    /// Zero out this object from memory using Rust intrinsics which ensure the
    /// zeroization operation is not "optimized away" by the compiler.
    fn zeroize(&mut self);
}


/// Use fences to prevent accesses from being reordered before this
/// point, which should hopefully help ensure that all accessors
/// see zeroes after this point.
#[inline]
fn atomic_fence() {
    atomic::compiler_fence(atomic::Ordering::SeqCst);
}

/// Perform a volatile write to the destination
#[inline]
fn volatile_write<T: Copy + Sized>(dst: &mut T, src: T) {
    unsafe { ptr::write_volatile(dst, src) }
}

/// Perform a volatile `memset` operation which fills a slice with a value
///
/// Safety:
/// The memory pointed to by `dst` must be a single allocated object that is valid for `count`
/// contiguous elements of `T`.
/// `count` must not be larger than an `isize`.
/// `dst` being offset by `mem::size_of::<T> * count` bytes must not wrap around the address space.
/// Also `dst` must be properly aligned.
#[inline]
unsafe fn volatile_set<T: Copy + Sized>(dst: *mut T, src: T, count: usize) {
    // TODO(tarcieri): use `volatile_set_memory` when stabilized
    for i in 0..count {
        // Safety:
        //
        // This is safe because there is room for at least `count` objects of type `T` in the
        // allocation pointed to by `dst`, because `count <= isize::MAX` and because
        // `dst.add(count)` must not wrap around the address space.
        let ptr = dst.add(i);
        // Safety:
        //
        // This is safe, because the pointer is valid and because `dst` is well aligned for `T` and
        // `ptr` is an offset of `dst` by a multiple of `mem::size_of::<T>()` bytes.
        ptr::write_volatile(ptr, src);
    }
}

impl<Z: DefaultIsZeroes> Zeroize for [Z] {
    fn zeroize(&mut self) {
        assert!(self.len() <= core::isize::MAX as usize);
        // Safety:
        //
        // This is safe, because the slice is well aligned and is backed by a single allocated
        // object for at least `self.len()` elements of type `Z`.
        // `self.len()` is also not larger than an `isize`, because of the assertion above.
        // The memory of the slice should not wrap around the address space.
        unsafe { volatile_set(self.as_mut_ptr(), Z::default(), self.len()) };
        atomic_fence();
    }
}


impl<'a, Z: Zeroize> Zeroize for IterMut<'a, Z> {
    fn zeroize(&mut self) {
        for elem in self {
            elem.zeroize();
        }
    }
}

pub trait DefaultIsZeroes: Copy + Default + Sized { }

impl<Z: DefaultIsZeroes> Zeroize for Z {
    fn zeroize(&mut self) {
        volatile_write(self, Z::default());
        atomic_fence();
    }
}

macro_rules! impl_zeroize_with_default {
    ($($type:ty),+) => {
        $(impl DefaultIsZeroes for $type {})+
    };
}

impl_zeroize_with_default!(i8, i16, i32, i64, i128, isize);
impl_zeroize_with_default!(u8, u16, u32, u64, u128, usize);
impl_zeroize_with_default!(f32, f64, char, bool);

/// Implement `Zeroize` on arrays of types that impl `Zeroize`
macro_rules! impl_zeroize_for_array {
    ($($size:expr),+) => {
        $(
            impl<Z: Zeroize> Zeroize for [Z; $size] {
                fn zeroize(&mut self) {
                    self.iter_mut().zeroize();
                }
            }
        )+
     };
}

// TODO(tarcieri): const generics
impl_zeroize_for_array!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
);

