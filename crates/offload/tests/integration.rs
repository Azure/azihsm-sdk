// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the `offload` proc macro.
//!
//! These tests exercise the macro with various parameter types and verify
//! that the generated struct, async methods, and worker thread work correctly.

use std::fmt;
use std::future::Future;
use std::pin::pin;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use offload::offload;

/// Spin-polling block_on. The generated futures return `Pending` until the
/// worker thread completes the operation, then `Ready` on a subsequent poll.
/// `Waker::noop()` means no wake notification, so we yield and re-poll.
fn block_on<T>(fut: impl Future<Output = T>) -> T {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(val) => return val,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

// ── Shared error type ──

#[derive(Debug)]
enum TestError {
    WorkerShutdown,
    Failed(String),
}

impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestError::WorkerShutdown => write!(f, "worker shutdown"),
            TestError::Failed(msg) => write!(f, "failed: {msg}"),
        }
    }
}

// ── Basic: by-value params, slice params, return types ──

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown)]
impl BasicWorker {
    pub fn add(a: usize, b: usize) -> Result<usize, TestError> {
        Ok(a + b)
    }

    pub fn echo_bytes(data: &[u8]) -> Result<Vec<u8>, TestError> {
        Ok(data.to_vec())
    }

    pub fn concat(a: &[u8], b: &[u8]) -> Result<Vec<u8>, TestError> {
        let mut result = a.to_vec();
        result.extend_from_slice(b);
        Ok(result)
    }
}

#[test]
fn test_basic_by_value() {
    let w = BasicWorker::new();
    let result = block_on(w.add(3, 4));
    assert_eq!(result.unwrap(), 7);
    w.shutdown();
}

#[test]
fn test_basic_slice_ref() {
    let w = BasicWorker::new();
    let data = b"hello world";
    let result = block_on(w.echo_bytes(data));
    assert_eq!(result.unwrap(), data);
    w.shutdown();
}

#[test]
fn test_basic_multiple_slices() {
    let w = BasicWorker::new();
    let result = block_on(w.concat(b"foo", b"bar"));
    assert_eq!(result.unwrap(), b"foobar");
    w.shutdown();
}

// ── Input slice -> mutable output slice, returns valid output length ──

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown)]
impl MutableOutWorker {
    pub fn tweak_and_copy(input: &[u8], output: &mut [u8]) -> Result<usize, TestError> {
        let count = input.len().min(output.len());
        for (dst, src) in output.iter_mut().zip(input.iter()).take(count) {
            *dst = src.wrapping_add(1);
        }
        Ok(count)
    }
}

#[test]
fn test_input_slice_to_mutable_output_slice() {
    let w = MutableOutWorker::new();
    let mut out = [0u8; 8];

    let len = block_on(w.tweak_and_copy(b"hello", &mut out)).unwrap();
    assert_eq!(len, 5);
    assert_eq!(&out[..len], b"ifmmp");
    assert_eq!(&out[len..], &[0, 0, 0]);

    w.shutdown();
}

// ── Option params ──

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown)]
impl OptionWorker {
    pub fn optional_slice(data: &[u8], prefix: Option<&[u8]>) -> Result<Vec<u8>, TestError> {
        let mut result = Vec::new();
        if let Some(p) = prefix {
            result.extend_from_slice(p);
        }
        result.extend_from_slice(data);
        Ok(result)
    }

    pub fn optional_mut_slice(input: &[u8], output: Option<&mut [u8]>) -> Result<usize, TestError> {
        if let Some(out) = output {
            let count = input.len().min(out.len());
            for (dst, src) in out.iter_mut().zip(input.iter()).take(count) {
                *dst = src.wrapping_add(1);
            }
            Ok(count)
        } else {
            Ok(0)
        }
    }
}

#[test]
fn test_option_slice_some() {
    let w = OptionWorker::new();
    let result = block_on(w.optional_slice(b"world", Some(b"hello ")));
    assert_eq!(result.unwrap(), b"hello world");
    w.shutdown();
}

#[test]
fn test_option_slice_none() {
    let w = OptionWorker::new();
    let result = block_on(w.optional_slice(b"alone", None));
    assert_eq!(result.unwrap(), b"alone");
    w.shutdown();
}

#[test]
fn test_option_mut_slice_some() {
    let w = OptionWorker::new();
    let mut out = [0u8; 8];

    let len = block_on(w.optional_mut_slice(b"hello", Some(&mut out))).unwrap();
    assert_eq!(len, 5);
    assert_eq!(&out[..len], b"ifmmp");
    assert_eq!(&out[len..], &[0, 0, 0]);

    w.shutdown();
}

#[test]
fn test_option_mut_slice_none() {
    let w = OptionWorker::new();
    let len = block_on(w.optional_mut_slice(b"hello", None)).unwrap();
    assert_eq!(len, 0);
    w.shutdown();
}

// ── Reference-to-non-slice (e.g., &String, &MyEnum) ──

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum Mode {
    Upper,
    Lower,
}

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown)]
impl RefWorker {
    pub fn transform(mode: &Mode, data: &[u8]) -> Result<Vec<u8>, TestError> {
        let s = std::str::from_utf8(data).map_err(|e| TestError::Failed(e.to_string()))?;
        let result = match mode {
            Mode::Upper => s.to_uppercase(),
            Mode::Lower => s.to_lowercase(),
        };
        Ok(result.into_bytes())
    }

    pub fn optional_transform(data: &[u8], mode: Option<&Mode>) -> Result<Vec<u8>, TestError> {
        let s = std::str::from_utf8(data).map_err(|e| TestError::Failed(e.to_string()))?;
        let result = match mode {
            Some(Mode::Upper) => s.to_uppercase(),
            Some(Mode::Lower) => s.to_lowercase(),
            None => s.to_string(),
        };
        Ok(result.into_bytes())
    }
}

#[test]
fn test_ref_non_slice() {
    let w = RefWorker::new();
    // &Mode in the handler becomes Mode by value in the async method
    let result = block_on(w.transform(Mode::Upper, b"hello"));
    assert_eq!(result.unwrap(), b"HELLO");
    w.shutdown();
}

#[test]
fn test_option_ref_some() {
    let w = RefWorker::new();
    // Option<&Mode> in the handler becomes Option<Mode> by value in the async method
    let result = block_on(w.optional_transform(b"heLLo", Some(Mode::Lower)));
    assert_eq!(result.unwrap(), b"hello");
    w.shutdown();
}

#[test]
fn test_option_ref_none() {
    let w = RefWorker::new();
    let result = block_on(w.optional_transform(b"Hello", None));
    assert_eq!(result.unwrap(), b"Hello");
    w.shutdown();
}

// ── Tuple return type ──

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown)]
impl TupleWorker {
    pub fn split_at(data: &[u8], pos: usize) -> Result<(Vec<u8>, Vec<u8>), TestError> {
        if pos > data.len() {
            return Err(TestError::Failed("pos out of range".into()));
        }
        Ok((data[..pos].to_vec(), data[pos..].to_vec()))
    }
}

#[test]
fn test_tuple_return() {
    let w = TupleWorker::new();
    let (left, right) = block_on(w.split_at(b"helloworld", 5)).unwrap();
    assert_eq!(left, b"hello");
    assert_eq!(right, b"world");
    w.shutdown();
}

// ── Error propagation ──

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown)]
impl ErrorWorker {
    pub fn failing_op(should_fail: bool) -> Result<u32, TestError> {
        if should_fail {
            Err(TestError::Failed("intentional failure".into()))
        } else {
            Ok(42)
        }
    }
}

#[test]
fn test_error_propagated() {
    let w = ErrorWorker::new();
    let ok = block_on(w.failing_op(false));
    assert_eq!(ok.unwrap(), 42);

    let err = block_on(w.failing_op(true));
    assert!(err.is_err());
    let msg = format!("{}", err.unwrap_err());
    assert!(msg.contains("intentional failure"));
    w.shutdown();
}

// ── Drop shuts down worker ──

#[test]
fn test_drop_shuts_down() {
    let w = ErrorWorker::new();
    let ok = block_on(w.failing_op(false));
    assert_eq!(ok.unwrap(), 42);
    drop(w);
    // If Drop didn't work, the thread would leak and the test process would hang.
}

// ── Bool return type ──

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown)]
impl BoolWorker {
    pub fn is_even(n: usize) -> Result<bool, TestError> {
        Ok(n % 2 == 0)
    }
}

#[test]
fn test_bool_return() {
    let w = BoolWorker::new();
    assert!(block_on(w.is_even(4)).unwrap());
    assert!(!block_on(w.is_even(7)).unwrap());
    w.shutdown();
}

// ── Multiple operations in sequence ──

#[test]
fn test_multiple_operations_sequence() {
    let w = BasicWorker::new();
    for i in 0..10 {
        let result = block_on(w.add(i, i));
        assert_eq!(result.unwrap(), i * 2);
    }
    w.shutdown();
}

// ── Future yields Pending before Ready ──

#[test]
fn test_future_is_not_immediately_ready() {
    let w = SingleThreadSlowWorker::new();
    let mut saw_pending = false;
    for _ in 0..10 {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(&waker);
        let mut fut = pin!(w.slow_add_single(1, 2));
        if let Poll::Pending = fut.as_mut().poll(&mut cx) {
            saw_pending = true;
            // Spin until ready so the worker processes the op before next iteration.
            loop {
                match fut.as_mut().poll(&mut cx) {
                    Poll::Ready(val) => {
                        assert_eq!(val.unwrap(), 3);
                        break;
                    }
                    Poll::Pending => std::thread::yield_now(),
                }
            }
        }
    }
    assert!(
        saw_pending,
        "expected at least one Pending across 10 iterations"
    );
    w.shutdown();
}

// ── 20 parallel async calls ──

#[test]
fn test_parallel_async_calls() {
    let w = BasicWorker::new();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);

    let mut futs: Vec<_> = (0..20).map(|i| Box::pin(w.add(i, i))).collect();
    let mut results: Vec<Option<Result<usize, TestError>>> = (0..20).map(|_| None).collect();

    loop {
        let mut all_done = true;
        for (idx, fut) in futs.iter_mut().enumerate() {
            if results[idx].is_some() {
                continue;
            }
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(val) => results[idx] = Some(val),
                Poll::Pending => all_done = false,
            }
        }
        if all_done {
            break;
        }
        std::thread::yield_now();
    }

    for i in 0..20 {
        assert_eq!(results[i].as_ref().unwrap().as_ref().unwrap(), &(i * 2));
    }
    w.shutdown();
}

// ── Shutdown then use returns WorkerShutdown ──

#[test]
fn test_use_after_shutdown() {
    let w = BasicWorker::new();
    w.shutdown();
    // Give the worker thread a moment to process the shutdown.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let result = block_on(w.add(1, 2));
    assert!(result.is_err());
}

// ── Multi-threaded worker ──

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown, workers = 1)]
impl SingleThreadSlowWorker {
    pub fn slow_add_single(a: usize, b: usize) -> Result<usize, TestError> {
        std::thread::sleep(std::time::Duration::from_millis(50));
        Ok(a + b)
    }
}

#[test]
fn test_single_worker_sequential_throughput() {
    // With 1 worker and 50ms per op, 4 concurrent ops must take at least 200ms.
    let w = SingleThreadSlowWorker::new();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);

    let mut futs: Vec<_> = (0..4).map(|i| Box::pin(w.slow_add_single(i, i))).collect();
    let mut results: Vec<Option<Result<usize, TestError>>> = (0..4).map(|_| None).collect();

    let start = std::time::Instant::now();
    loop {
        let mut all_done = true;
        for (idx, fut) in futs.iter_mut().enumerate() {
            if results[idx].is_some() {
                continue;
            }
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(val) => results[idx] = Some(val),
                Poll::Pending => all_done = false,
            }
        }
        if all_done {
            break;
        }
        std::thread::yield_now();
    }
    let elapsed = start.elapsed();

    for i in 0..4 {
        assert_eq!(results[i].as_ref().unwrap().as_ref().unwrap(), &(i * 2));
    }
    // 4 ops at 50ms each on 1 worker = at least 200ms sequential.
    assert!(
        elapsed >= std::time::Duration::from_millis(200),
        "expected sequential execution (~200ms) but finished in {elapsed:?}"
    );
    w.shutdown();
}

#[offload(error = TestError, shutdown_error = TestError::WorkerShutdown, workers = 10)]
impl MultiThreadWorker {
    pub fn slow_add(a: usize, b: usize) -> Result<usize, TestError> {
        std::thread::sleep(std::time::Duration::from_millis(50));
        Ok(a + b)
    }
}

#[test]
fn test_multi_thread_basic() {
    let w = MultiThreadWorker::new();
    let result = block_on(w.slow_add(10, 20));
    assert_eq!(result.unwrap(), 30);
    w.shutdown();
}

#[test]
fn test_multi_thread_parallel_throughput() {
    // With 10 workers and 50ms per op, 10 concurrent ops should complete in
    // roughly 50ms rather than 500ms.
    let w = MultiThreadWorker::new();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);

    let mut futs: Vec<_> = (0..10).map(|i| Box::pin(w.slow_add(i, i))).collect();
    let mut results: Vec<Option<Result<usize, TestError>>> = (0..10).map(|_| None).collect();

    let start = std::time::Instant::now();
    loop {
        let mut all_done = true;
        for (idx, fut) in futs.iter_mut().enumerate() {
            if results[idx].is_some() {
                continue;
            }
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(val) => results[idx] = Some(val),
                Poll::Pending => all_done = false,
            }
        }
        if all_done {
            break;
        }
        std::thread::yield_now();
    }
    let elapsed = start.elapsed();

    for i in 0..10 {
        assert_eq!(results[i].as_ref().unwrap().as_ref().unwrap(), &(i * 2));
    }
    // 10 ops at 50ms each sequentially = 500ms.  With 10 workers should be ~50ms.
    // Use a generous upper bound to avoid flaky tests.
    assert!(
        elapsed < std::time::Duration::from_millis(180),
        "expected parallel execution but took {elapsed:?}"
    );
    w.shutdown();
}

#[test]
fn test_multi_thread_drop_shuts_down() {
    let w = MultiThreadWorker::new();
    let _ = block_on(w.slow_add(1, 1));
    drop(w);
    // If Drop didn't shut down all threads, the test process would hang.
}
