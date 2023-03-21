use casper_types::EraId;
use datasize::DataSize;

use crate::types::{BlockHash, BlockHeader, MetaBlock, MetaBlockMergeError, MetaBlockState};

#[derive(Clone, DataSize, Debug, PartialEq)]
pub(crate) enum LazyBlock {
    NotPresent,
    MetaBlock(MetaBlock),
    Stored(BlockHash, BlockHeader, MetaBlockState),
}

impl LazyBlock {
    pub(super) fn block_hash(&self) -> Option<BlockHash> {
        match self {
            LazyBlock::NotPresent => None,
            LazyBlock::MetaBlock(meta_block) => Some(*meta_block.block.hash()),
            LazyBlock::Stored(block_hash, _, _) => Some(*block_hash),
        }
    }

    pub(super) fn height(&self) -> Option<u64> {
        match self {
            LazyBlock::NotPresent => None,
            LazyBlock::MetaBlock(meta_block) => Some(meta_block.block.height()),
            LazyBlock::Stored(_, header, _) => Some(header.height()),
        }
    }

    pub(super) fn era_id(&self) -> Option<EraId> {
        match self {
            LazyBlock::NotPresent => None,
            LazyBlock::MetaBlock(meta_block) => Some(meta_block.block.header().era_id()),
            LazyBlock::Stored(_, header, _) => Some(header.era_id()),
        }
    }

    pub(super) fn state(&self) -> Option<&MetaBlockState> {
        match self {
            LazyBlock::NotPresent => None,
            LazyBlock::MetaBlock(meta_block) => Some(&meta_block.state),
            LazyBlock::Stored(_, _, state) => Some(state),
        }
    }

    pub(super) fn state_mut(&mut self) -> Option<&mut MetaBlockState> {
        match self {
            LazyBlock::NotPresent => None,
            LazyBlock::MetaBlock(meta_block) => Some(&mut meta_block.state),
            LazyBlock::Stored(_, _, state) => Some(state),
        }
    }

    pub(super) fn block_header(&self) -> Option<&BlockHeader> {
        match self {
            LazyBlock::NotPresent => None,
            LazyBlock::Stored(_, header, _) => Some(header),
            LazyBlock::MetaBlock(meta_block) => Some(meta_block.block.header()),
        }
    }

    pub(super) fn meta_block(&mut self) -> Option<&mut MetaBlock> {
        match self {
            LazyBlock::NotPresent | LazyBlock::Stored(..) => None,
            LazyBlock::MetaBlock(meta_block) => Some(meta_block),
        }
    }

    pub(super) fn merge_or_insert_meta_block(
        &mut self,
        other: MetaBlock,
    ) -> Result<(), MetaBlockMergeError> {
        let new_self = match self {
            LazyBlock::NotPresent => LazyBlock::MetaBlock(other),
            LazyBlock::MetaBlock(meta_block) => {
                LazyBlock::MetaBlock(meta_block.clone().merge(other)?)
            }
            LazyBlock::Stored(block_hash, header, state) => {
                let merged_state = state.merge(other.state)?;
                LazyBlock::Stored(*block_hash, header.clone(), merged_state)
            }
        };
        *self = new_self;
        Ok(())
    }
}
