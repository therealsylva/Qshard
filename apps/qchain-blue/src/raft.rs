#![forbid(unsafe_code)]

use std::{fmt::Debug, sync::Arc};

use openraft::{
    BasicNode, Raft, RaftNetwork, RaftNetworkFactory,
    error::{InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Unreachable},
    network::RPCOption,
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
};
use openraft_sledstore::TypeConfig;
use reqwest::Client;
use serde::{Serialize, de::DeserializeOwned};

pub type NodeId = u64;
pub type QchainRaft = Raft<TypeConfig>;

#[derive(Clone)]
pub struct NetworkFactory {
    client: Client,
    cluster_token: Arc<String>,
}

impl NetworkFactory {
    pub fn new(client: Client, cluster_token: String) -> Self {
        Self {
            client,
            cluster_token: Arc::new(cluster_token),
        }
    }
}

pub struct NetworkConnection {
    target: NodeId,
    node: BasicNode,
    client: Client,
    cluster_token: Arc<String>,
}

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = NetworkConnection;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        NetworkConnection {
            target,
            node: node.clone(),
            client: self.client.clone(),
            cluster_token: Arc::clone(&self.cluster_token),
        }
    }
}

impl NetworkConnection {
    async fn request<Req, Resp, Err>(
        &self,
        path: &str,
        request: &Req,
        option: &RPCOption,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, Err>>
    where
        Req: Serialize + ?Sized,
        Resp: DeserializeOwned,
        Err: std::error::Error + Serialize + DeserializeOwned + Debug,
    {
        let url = format!(
            "{}/{}",
            self.node.addr.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let response = self
            .client
            .post(url)
            .header("x-qchain-cluster-token", self.cluster_token.as_str())
            .timeout(option.soft_ttl())
            .json(request)
            .send()
            .await
            .map_err(|error| {
                if error.is_connect() || error.is_timeout() {
                    RPCError::Unreachable(Unreachable::new(&error))
                } else {
                    RPCError::Network(NetworkError::new(&error))
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            let error = std::io::Error::other(format!("Raft peer returned HTTP {status}"));
            return Err(RPCError::Network(NetworkError::new(&error)));
        }
        let result = response
            .json::<Result<Resp, Err>>()
            .await
            .map_err(|error| RPCError::Network(NetworkError::new(&error)))?;
        result.map_err(|error| {
            RPCError::RemoteError(RemoteError::new_with_node(
                self.target,
                self.node.clone(),
                error,
            ))
        })
    }
}

impl RaftNetwork<TypeConfig> for NetworkConnection {
    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.request("/v1/raft/append", &request, &option).await
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        self.request("/v1/raft/snapshot", &request, &option).await
    }

    async fn vote(
        &mut self,
        request: VoteRequest<NodeId>,
        option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.request("/v1/raft/vote", &request, &option).await
    }
}
