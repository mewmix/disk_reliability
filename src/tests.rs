'''
#[cfg(test)]
mod tests {
    use crate::{run_lean_test, LeanTest};
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use tempfile::tempdir;
    use std::sync::Arc;
    use parking_lot::Mutex;
    use crate::{full_reliability_test, ErrorCounters, DataTypePattern};


    #[test]
    fn test_lean_seq1m_q8t1() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_lean.bin");
        let results = run_lean_test(&path, LeanTest::Seq1Mq8t1, false, false).unwrap();
        assert!(results["write_iops"] > 0.0);
        assert!(results["read_iops"] > 0.0);
    }

    #[test]
    fn test_lean_seq1m_q1t1() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_lean.bin");
        let results = run_lean_test(&path, LeanTest::Seq1Mq1t1, false, false).unwrap();
        assert!(results["write_iops"] > 0.0);
        assert!(results["read_iops"] > 0.0);
    }

    #[test]
    fn test_lean_rnd4k_q32t1() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_lean.bin");
        let results = run_lean_test(&path, LeanTest::Rnd4kQ32T1, false, false).unwrap();
        assert!(results["write_iops"] > 0.0);
        assert!(results["read_iops"] > 0.0);
    }

    #[test]
    fn test_lean_rnd4k_q1t1() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_lean.bin");
        let results = run_lean_test(&path, LeanTest::Rnd4kQ1t1, false, false).unwrap();
        assert!(results["write_iops"] > 0.0);
        assert!(results["read_iops"] > 0.0);
    }

    #[test]
    fn test_full_reliability_test_simple() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_full.bin");
        let log_f_opt: Option<Arc<Mutex<File>>> = None;
        let counters_arc = Arc::new(ErrorCounters::new());
        let test_size = Some(1024 * 1024); // 1MB
        let block_size = 4096;
        let data_pattern = DataTypePattern::Binary;

        let result = full_reliability_test(
            &path,
            &log_f_opt,
            &counters_arc,
            test_size,
            0,
            block_size,
            1,
            4,
            data_pattern,
            16,
            false,
            false,
            false,
            false,
        );
        assert!(result.is_ok());
        assert_eq!(counters_arc.mismatches.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(counters_arc.read_errors.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(counters_arc.write_errors.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
'''