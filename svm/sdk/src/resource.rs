use core::mem::ManuallyDrop;

/// A linear type wrapper: panics (in WASM: traps) if dropped without explicit consumption.
///
/// Wrap values that must be explicitly accounted for — e.g. token amounts read from UTXOs —
/// to prevent accidental silent discards in contract logic.
///
/// # Example
///
/// ```
/// use sophis_sdk::Resource;
///
/// let r = Resource::new(100u64);
/// let value = r.consume(); // must call consume() — panics otherwise
/// assert_eq!(value, 100);
/// ```
pub struct Resource<T> {
    inner: ManuallyDrop<T>,
    consumed: bool,
}

impl<T> Resource<T> {
    pub fn new(value: T) -> Self {
        Self { inner: ManuallyDrop::new(value), consumed: false }
    }

    /// Consumes the resource and returns the wrapped value.
    pub fn consume(mut self) -> T {
        self.consumed = true;
        // Safety: we set consumed = true, so Drop will not double-drop.
        let value = unsafe { ManuallyDrop::take(&mut self.inner) };
        core::mem::forget(self);
        value
    }

    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> &T {
        &self.inner
    }

    #[allow(clippy::should_implement_trait)]
    pub fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> Drop for Resource<T> {
    fn drop(&mut self) {
        if !self.consumed {
            // Drop the inner value to avoid a memory leak before panicking.
            // Safety: `consumed` is false, so `inner` has not been taken yet.
            unsafe { ManuallyDrop::drop(&mut self.inner) };
            panic!("Resource<{}> dropped without consuming — potential resource leak in contract", core::any::type_name::<T>());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_returns_value() {
        let r = Resource::new(42u64);
        assert_eq!(r.consume(), 42);
    }

    #[test]
    fn as_ref_does_not_consume() {
        let r = Resource::new(99u32);
        assert_eq!(*r.as_ref(), 99);
        let _ = r.consume();
    }

    #[test]
    #[should_panic(expected = "Resource<u64> dropped without consuming")]
    fn drop_without_consume_panics() {
        let _r = Resource::new(7u64);
        // Not consumed → Drop panics
    }

    #[test]
    fn as_mut_allows_mutation_before_consume() {
        let mut r = Resource::new(1u64);
        *r.as_mut() = 2;
        assert_eq!(r.consume(), 2);
    }
}
