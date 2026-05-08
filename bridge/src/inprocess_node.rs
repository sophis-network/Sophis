use std::sync::Arc;

use sophis_core::signals::Shutdown;
use sophis_utils::fd_budget;
use sophisd_lib::{args as sophisd_args, daemon as sophisd_daemon};

pub(crate) struct InProcessNode {
    core: Arc<sophis_core::core::Core>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl InProcessNode {
    pub(crate) fn start_from_args(args: sophisd_args::Args) -> Result<Self, anyhow::Error> {
        let _ = fd_budget::try_set_fd_limit(sophisd_daemon::DESIRED_DAEMON_SOFT_FD_LIMIT);

        let runtime = sophisd_daemon::Runtime::from_args(&args);
        let fd_total_budget =
            fd_budget::limit() - args.rpc_max_clients as i32 - args.inbound_limit as i32 - args.outbound_target as i32;
        let (core, _) = sophisd_daemon::create_core_with_runtime(&runtime, &args, fd_total_budget);
        let workers = core.start();
        Ok(Self { core, workers })
    }

    fn shutdown(self) {
        self.core.shutdown();
        self.core.join(self.workers);
    }
}

pub(crate) async fn shutdown_inprocess(node: InProcessNode) {
    let _ = tokio::task::spawn_blocking(move || node.shutdown()).await;
}
