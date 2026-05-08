use sophis_consensus_core::{
    BlockHashMap, BlockHashSet,
    coinbase::*,
    config::params::ForkedParam,
    errors::coinbase::{CoinbaseError, CoinbaseResult},
    subnets,
    tx::{ScriptPublicKey, ScriptVec, Transaction, TransactionOutput},
};
use std::convert::TryInto;

use crate::{constants, model::stores::ghostdag::GhostdagData};

const LENGTH_OF_BLUE_SCORE: usize = size_of::<u64>();
const LENGTH_OF_SUBSIDY: usize = size_of::<u64>();
const LENGTH_OF_SCRIPT_PUB_KEY_VERSION: usize = size_of::<u16>();
const LENGTH_OF_SCRIPT_PUB_KEY_LENGTH: usize = size_of::<u8>();

const MIN_PAYLOAD_LENGTH: usize =
    LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY + LENGTH_OF_SCRIPT_PUB_KEY_VERSION + LENGTH_OF_SCRIPT_PUB_KEY_LENGTH;

// We define a year as 365.25 days and a month as 365.25 / 12 = 30.4375
// SECONDS_PER_MONTH = 30.4375 * 24 * 60 * 60
const SECONDS_PER_MONTH: u64 = 2629800;

pub const SUBSIDY_BY_MONTH_TABLE_SIZE: usize = 1902;
pub type SubsidyByMonthTable = [u64; SUBSIDY_BY_MONTH_TABLE_SIZE];

#[derive(Clone)]
pub struct CoinbaseManager {
    coinbase_payload_script_public_key_max_len: u8,
    max_coinbase_payload_len: usize,
    deflationary_phase_daa_score: u64,
    pre_deflationary_phase_base_subsidy: u64,
    bps_history: ForkedParam<u64>,

    /// Precomputed subsidy by month tables (for before and after the Crescendo hardfork)
    subsidy_by_month_table_before: SubsidyByMonthTable,
    subsidy_by_month_table_after: SubsidyByMonthTable,

    /// The crescendo activation DAA score where BPS increased from 1 to 10.
    /// This score is required here long-term (and not only for the actual forking), in
    /// order to correctly determine the subsidy month from the live DAA score of the network
    crescendo_activation_daa_score: u64,
}

/// Struct used to streamline payload parsing
struct PayloadParser<'a> {
    remaining: &'a [u8], // The unparsed remainder
}

impl<'a> PayloadParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }

    /// Returns a slice with the first `n` bytes of `remaining`, while setting `remaining` to the remaining part
    fn take(&mut self, n: usize) -> &[u8] {
        let (segment, remaining) = self.remaining.split_at(n);
        self.remaining = remaining;
        segment
    }
}

impl CoinbaseManager {
    pub fn new(
        coinbase_payload_script_public_key_max_len: u8,
        max_coinbase_payload_len: usize,
        deflationary_phase_daa_score: u64,
        pre_deflationary_phase_base_subsidy: u64,
        bps_history: ForkedParam<u64>,
    ) -> Self {
        // Precomputed subsidy by month table for the actual block per second rate
        // Here values are rounded up so that we keep the same number of rewarding months as in the original 1 BPS table.
        // In a 10 BPS network, the induced increase in total rewards is ~42 SPHS (see tests::calc_high_bps_total_rewards_delta())
        let subsidy_by_month_table_before: SubsidyByMonthTable =
            core::array::from_fn(|i| SUBSIDY_BY_MONTH_TABLE[i].div_ceil(bps_history.before()));
        let subsidy_by_month_table_after: SubsidyByMonthTable =
            core::array::from_fn(|i| SUBSIDY_BY_MONTH_TABLE[i].div_ceil(bps_history.after()));
        Self {
            coinbase_payload_script_public_key_max_len,
            max_coinbase_payload_len,
            deflationary_phase_daa_score,
            pre_deflationary_phase_base_subsidy,
            bps_history,
            subsidy_by_month_table_before,
            subsidy_by_month_table_after,
            crescendo_activation_daa_score: bps_history.activation().daa_score(),
        }
    }

    #[cfg(test)]
    #[inline]
    pub fn bps(&self) -> ForkedParam<u64> {
        self.bps_history
    }

    pub fn expected_coinbase_transaction<T: AsRef<[u8]>>(
        &self,
        daa_score: u64,
        miner_data: MinerData<T>,
        ghostdag_data: &GhostdagData,
        mergeset_rewards: &BlockHashMap<BlockRewardData>,
        mergeset_non_daa: &BlockHashSet,
    ) -> CoinbaseResult<CoinbaseTransactionTemplate> {
        // + 1 for possible red reward
        let mut outputs = Vec::with_capacity(ghostdag_data.mergeset_blues.len() + 1);

        // Add an output for each mergeset blue block (∩ DAA window), paying to the script reported by the block.
        // Note that combinatorically it is nearly impossible for a blue block to be non-DAA.
        // 100% of subsidy + fees goes to the miner — no devfund split (eliminated 2026-05-04).
        for blue in ghostdag_data.mergeset_blues.iter().filter(|h| !mergeset_non_daa.contains(h)) {
            let reward_data = mergeset_rewards.get(blue).unwrap();
            if reward_data.subsidy + reward_data.total_fees > 0 {
                outputs
                    .push(TransactionOutput::new(reward_data.subsidy + reward_data.total_fees, reward_data.script_public_key.clone()));
            }
        }

        // Collect all rewards from mergeset reds ∩ DAA window and create a
        // single output rewarding all to the current block (the "merging" block).
        let mut red_reward = 0u64;

        for red in ghostdag_data.mergeset_reds.iter() {
            let reward_data = mergeset_rewards.get(red).unwrap();
            if mergeset_non_daa.contains(red) {
                red_reward += reward_data.total_fees;
            } else {
                red_reward += reward_data.subsidy + reward_data.total_fees;
            }
        }

        if red_reward > 0 {
            outputs.push(TransactionOutput::new(red_reward, miner_data.script_public_key.clone()));
        }

        // Build the current block's payload
        let subsidy = self.calc_block_subsidy(daa_score);
        let payload = self.serialize_coinbase_payload(&CoinbaseData { blue_score: ghostdag_data.blue_score, subsidy, miner_data })?;

        Ok(CoinbaseTransactionTemplate {
            tx: Transaction::new(constants::TX_VERSION, vec![], outputs, 0, subnets::SUBNETWORK_ID_COINBASE, 0, payload),
            has_red_reward: red_reward > 0,
        })
    }

    pub fn serialize_coinbase_payload<T: AsRef<[u8]>>(&self, data: &CoinbaseData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = data.miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }
        let payload: Vec<u8> = data.blue_score.to_le_bytes().iter().copied()                    // Blue score                   (u64)
            .chain(data.subsidy.to_le_bytes().iter().copied())                                  // Subsidy                      (u64)
            .chain(data.miner_data.script_public_key.version().to_le_bytes().iter().copied())   // Script public key version    (u16)
            .chain((script_pub_key_len as u8).to_le_bytes().iter().copied())                    // Script public key length     (u8)
            .chain(data.miner_data.script_public_key.script().iter().copied())                  // Script public key            
            .chain(data.miner_data.extra_data.as_ref().iter().copied())                         // Extra data
            .collect();

        Ok(payload)
    }

    pub fn modify_coinbase_payload<T: AsRef<[u8]>>(&self, mut payload: Vec<u8>, miner_data: &MinerData<T>) -> CoinbaseResult<Vec<u8>> {
        let script_pub_key_len = miner_data.script_public_key.script().len();
        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len as usize {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        // Keep only blue score and subsidy. Note that truncate does not modify capacity, so
        // the usual case where the payloads are the same size will not trigger a reallocation
        payload.truncate(LENGTH_OF_BLUE_SCORE + LENGTH_OF_SUBSIDY);
        payload.extend(
            miner_data.script_public_key.version().to_le_bytes().iter().copied() // Script public key version (u16)
                .chain((script_pub_key_len as u8).to_le_bytes().iter().copied()) // Script public key length  (u8)
                .chain(miner_data.script_public_key.script().iter().copied())    // Script public key
                .chain(miner_data.extra_data.as_ref().iter().copied()), // Extra data
        );

        Ok(payload)
    }

    pub fn deserialize_coinbase_payload<'a>(&self, payload: &'a [u8]) -> CoinbaseResult<CoinbaseData<&'a [u8]>> {
        if payload.len() < MIN_PAYLOAD_LENGTH {
            return Err(CoinbaseError::PayloadLenBelowMin(payload.len(), MIN_PAYLOAD_LENGTH));
        }

        if payload.len() > self.max_coinbase_payload_len {
            return Err(CoinbaseError::PayloadLenAboveMax(payload.len(), self.max_coinbase_payload_len));
        }

        let mut parser = PayloadParser::new(payload);

        let blue_score = u64::from_le_bytes(parser.take(LENGTH_OF_BLUE_SCORE).try_into().unwrap());
        let subsidy = u64::from_le_bytes(parser.take(LENGTH_OF_SUBSIDY).try_into().unwrap());
        let script_pub_key_version = u16::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_VERSION).try_into().unwrap());
        let script_pub_key_len = u8::from_le_bytes(parser.take(LENGTH_OF_SCRIPT_PUB_KEY_LENGTH).try_into().unwrap());

        if script_pub_key_len > self.coinbase_payload_script_public_key_max_len {
            return Err(CoinbaseError::PayloadScriptPublicKeyLenAboveMax(
                script_pub_key_len as usize,
                self.coinbase_payload_script_public_key_max_len,
            ));
        }

        if parser.remaining.len() < script_pub_key_len as usize {
            return Err(CoinbaseError::PayloadCantContainScriptPublicKey(
                payload.len(),
                MIN_PAYLOAD_LENGTH + script_pub_key_len as usize,
            ));
        }

        let script_public_key =
            ScriptPublicKey::new(script_pub_key_version, ScriptVec::from_slice(parser.take(script_pub_key_len as usize)));
        let extra_data = parser.remaining;

        Ok(CoinbaseData { blue_score, subsidy, miner_data: MinerData { script_public_key, extra_data } })
    }

    pub fn calc_block_subsidy(&self, daa_score: u64) -> u64 {
        if daa_score < self.deflationary_phase_daa_score {
            return self.pre_deflationary_phase_base_subsidy;
        }

        let subsidy_month = self.subsidy_month(daa_score) as usize;
        let subsidy_table = if self.bps_history.activation().is_active(daa_score) {
            &self.subsidy_by_month_table_after
        } else {
            &self.subsidy_by_month_table_before
        };
        subsidy_table[subsidy_month.min(subsidy_table.len() - 1)]
    }

    /// Get the subsidy month as function of the current DAA score.
    ///
    /// Note that this function is called only if daa_score >= self.deflationary_phase_daa_score
    fn subsidy_month(&self, daa_score: u64) -> u64 {
        let seconds_since_deflationary_phase_started = if self.crescendo_activation_daa_score < self.deflationary_phase_daa_score {
            // crescendo_activation < deflationary_phase <= daa_score (activated before deflation)
            (daa_score - self.deflationary_phase_daa_score) / self.bps_history.after()
        } else if daa_score < self.crescendo_activation_daa_score {
            // deflationary_phase <= daa_score < crescendo_activation (pre activation)
            (daa_score - self.deflationary_phase_daa_score) / self.bps_history.before()
        } else {
            // Else - deflationary_phase <= crescendo_activation <= daa_score.
            // Count seconds differently before and after Crescendo activation
            (self.crescendo_activation_daa_score - self.deflationary_phase_daa_score) / self.bps_history.before()
                + (daa_score - self.crescendo_activation_daa_score) / self.bps_history.after()
        };

        seconds_since_deflationary_phase_started / SECONDS_PER_MONTH
    }

    #[cfg(test)]
    pub fn legacy_calc_block_subsidy(&self, daa_score: u64) -> u64 {
        if daa_score < self.deflationary_phase_daa_score {
            return self.pre_deflationary_phase_base_subsidy;
        }

        // Note that this calculation implicitly assumes that block per second = 1 (by assuming daa score diff is in second units).
        let months_since_deflationary_phase_started = (daa_score - self.deflationary_phase_daa_score) / SECONDS_PER_MONTH;
        assert!(months_since_deflationary_phase_started <= usize::MAX as u64);
        let months_since_deflationary_phase_started: usize = months_since_deflationary_phase_started as usize;
        if months_since_deflationary_phase_started >= SUBSIDY_BY_MONTH_TABLE.len() {
            *SUBSIDY_BY_MONTH_TABLE.last().unwrap()
        } else {
            SUBSIDY_BY_MONTH_TABLE[months_since_deflationary_phase_started]
        }
    }
}

/*
    This table was pre-calculated using the formula floor(54_089_972 / 2^(month/74)) for all months
    until reaching 0 subsidy. The halving period of 74 months (~6.17 years) was chosen so that
    exactly 75% of the total supply is mined within the first 10 years from genesis (including the
    pre-deflationary phase). The initial value (54_089_972) was chosen so that total emission
    (pre-deflationary + deflationary) fits within MAX_SOMPI = 210_000_000 * SOMPI_PER_SOPHIS.
    These values represent the reward per second for each month (= reward per block for 1 BPS).
    Total emission at 1 BPS ≈ 209_999_972 SPHS ≤ MAX_SOMPI (210_000_000 SPHS).
    At year 10 the per-block subsidy (~18.6M sompi/s) matches the difficulty level of the
    final 5% tail in the original schedule, giving a smooth long tail for the remaining 25%.
*/
#[rustfmt::skip]
const SUBSIDY_BY_MONTH_TABLE: [u64; SUBSIDY_BY_MONTH_TABLE_SIZE] = [
	54089972, 53585684, 53086098, 52591170, 52100856, 51615114, 51133900, 50657172, 50184889, 49717009, 49253492, 48794295, 48339380, 47888706, 47442234, 46999924, 46561738, 46127638, 45697584, 45271540, 44849468, 44431331, 44017092, 43606715, 43200165,
	42797404, 42398399, 42003113, 41611513, 41223564, 40839232, 40458483, 40081283, 39707601, 39337402, 38970654, 38607326, 38247385, 37890800, 37537540, 37187573, 36840869, 36497397, 36157127, 35820030, 35486075, 35155234, 34827478, 34502777, 34181103,
	33862429, 33546725, 33233965, 32924121, 32617165, 32313071, 32011813, 31713363, 31417695, 31124784, 30834604, 30547129, 30262335, 29980195, 29700686, 29423783, 29149462, 28877698, 28608467, 28341747, 28077514, 27815743, 27556414, 27299502, 27044986,
	26792842, 26543049, 26295585, 26050428, 25807557, 25566950, 25328586, 25092444, 24858504, 24626746, 24397147, 24169690, 23944353, 23721117, 23499962, 23280869, 23063819, 22848792, 22635770, 22424734, 22215665, 22008546, 21803357, 21600082, 21398702,
	21199199, 21001556, 20805756, 20611782, 20419616, 20229241, 20040641, 19853800, 19668701, 19485327, 19303663, 19123692, 18945400, 18768770, 18593786, 18420434, 18248698, 18078563, 17910015, 17743037, 17577617, 17413739, 17251388, 17090551, 16931214,
	16773362, 16616982, 16462060, 16308582, 16156535, 16005906, 15856681, 15708847, 15562392, 15417302, 15273564, 15131167, 14990097, 14850343, 14711891, 14574731, 14438849, 14304233, 14170873, 14038757, 13907871, 13778207, 13649751, 13522493, 13396421,
	13271524, 13147792, 13025214, 12903778, 12783475, 12664293, 12546222, 12429252, 12313373, 12198573, 12084845, 11972176, 11860558, 11749981, 11640434, 11531909, 11424396, 11317885, 11212367, 11107832, 11004273, 10901678, 10800041, 10699351, 10599599,
	10500778, 10402878, 10305891, 10209808, 10114620, 10020320, 9926900, 9834350, 9742663, 9651831, 9561846, 9472700, 9384385, 9296893, 9210217, 9124349, 9039281, 8955007, 8871518, 8788808, 8706869, 8625694, 8545275, 8465607, 8386681,
	8308491, 8231030, 8154291, 8078267, 8002953, 7928340, 7854423, 7781196, 7708651, 7636782, 7565583, 7495048, 7425171, 7355945, 7287365, 7219424, 7152116, 7085436, 7019378, 6953935, 6889103, 6824875, 6761246, 6698210, 6635762,
	6573896, 6512607, 6451889, 6391737, 6332146, 6273111, 6214626, 6156686, 6099286, 6042422, 5986088, 5930279, 5874990, 5820217, 5765954, 5712198, 5658942, 5606183, 5553916, 5502136, 5450839, 5400020, 5349675, 5299799, 5250389,
	5201439, 5152945, 5104904, 5057310, 5010160, 4963450, 4917175, 4871331, 4825915, 4780923, 4736350, 4692192, 4648446, 4605108, 4562174, 4519640, 4477503, 4435759, 4394404, 4353434, 4312847, 4272637, 4232803, 4193340, 4154245,
	4115515, 4077145, 4039133, 4001476, 3964170, 3927211, 3890598, 3854325, 3818391, 3782791, 3747524, 3712585, 3677972, 3643682, 3609712, 3576058, 3542718, 3509689, 3476967, 3444551, 3412437, 3380623, 3349105, 3317881, 3286948,
	3256303, 3225944, 3195868, 3166073, 3136555, 3107313, 3078343, 3049643, 3021211, 2993044, 2965139, 2937495, 2910108, 2882977, 2856099, 2829471, 2803091, 2776958, 2751068, 2725419, 2700010, 2674837, 2649899, 2625194, 2600719,
	2576472, 2552452, 2528655, 2505080, 2481725, 2458587, 2435665, 2412957, 2390461, 2368175, 2346096, 2324223, 2302554, 2281087, 2259820, 2238751, 2217879, 2197202, 2176717, 2156423, 2136318, 2116401, 2096670, 2077122, 2057757,
	2038572, 2019566, 2000738, 1982085, 1963605, 1945299, 1927162, 1909195, 1891395, 1873762, 1856292, 1838986, 1821841, 1804856, 1788029, 1771359, 1754844, 1738483, 1722275, 1706218, 1690311, 1674552, 1658940, 1643474, 1628151,
	1612972, 1597934, 1583036, 1568277, 1553656, 1539171, 1524821, 1510605, 1496522, 1482569, 1468747, 1455054, 1441488, 1428049, 1414735, 1401545, 1388479, 1375534, 1362709, 1350005, 1337418, 1324949, 1312597, 1300359, 1288236,
	1276226, 1264327, 1252540, 1240862, 1229293, 1217832, 1206478, 1195230, 1184087, 1173048, 1162111, 1151277, 1140543, 1129910, 1119375, 1108939, 1098601, 1088358, 1078211, 1068159, 1058200, 1048335, 1038561, 1028878, 1019286,
	1009783, 1000369, 991042, 981802, 972649, 963581, 954597, 945697, 936881, 928146, 919493, 910920, 902428, 894014, 885679, 877422, 869241, 861137, 853109, 845155, 837276, 829470, 821737, 814075, 806486,
	798967, 791518, 784138, 776828, 769585, 762410, 755302, 748261, 741284, 734373, 727527, 720744, 714024, 707367, 700772, 694239, 687767, 681354, 675002, 668709, 662474, 656298, 650179, 644118, 638113,
	632163, 626270, 620431, 614646, 608916, 603239, 597615, 592043, 586524, 581055, 575638, 570271, 564955, 559687, 554469, 549300, 544179, 539105, 534079, 529100, 524167, 519280, 514439, 509643, 504891,
	500184, 495521, 490901, 486324, 481790, 477298, 472848, 468440, 464073, 459746, 455460, 451214, 447007, 442839, 438711, 434620, 430568, 426554, 422577, 418638, 414735, 410868, 407037, 403243, 399483,
	395759, 392069, 388414, 384792, 381205, 377651, 374130, 370642, 367186, 363763, 360372, 357012, 353683, 350386, 347119, 343883, 340677, 337501, 334354, 331237, 328149, 325089, 322059, 319056, 316081,
	313135, 310215, 307323, 304458, 301619, 298807, 296021, 293262, 290527, 287819, 285135, 282477, 279843, 277234, 274650, 272089, 269552, 267039, 264550, 262083, 259640, 257219, 254821, 252445, 250092,
	247760, 245450, 243162, 240895, 238649, 236424, 234220, 232036, 229873, 227730, 225607, 223503, 221419, 219355, 217310, 215284, 213277, 211288, 209319, 207367, 205434, 203518, 201621, 199741, 197879,
	196034, 194207, 192396, 190602, 188825, 187065, 185321, 183593, 181881, 180186, 178506, 176841, 175193, 173559, 171941, 170338, 168750, 167177, 165618, 164074, 162544, 161029, 159528, 158040, 156567,
	155107, 153661, 152229, 150809, 149403, 148010, 146631, 145263, 143909, 142567, 141238, 139921, 138617, 137325, 136044, 134776, 133519, 132275, 131041, 129820, 128609, 127410, 126222, 125046, 123880,
	122725, 121581, 120447, 119324, 118212, 117110, 116018, 114936, 113865, 112803, 111751, 110709, 109677, 108655, 107642, 106638, 105644, 104659, 103683, 102717, 101759, 100810, 99870, 98939, 98017,
	97103, 96198, 95301, 94412, 93532, 92660, 91796, 90940, 90093, 89253, 88420, 87596, 86779, 85970, 85169, 84375, 83588, 82809, 82037, 81272, 80514, 79764, 79020, 78283, 77553,
	76830, 76114, 75404, 74701, 74005, 73315, 72631, 71954, 71283, 70619, 69960, 69308, 68662, 68022, 67388, 66759, 66137, 65520, 64910, 64304, 63705, 63111, 62523, 61940, 61362,
	60790, 60223, 59662, 59106, 58555, 58009, 57468, 56932, 56401, 55875, 55354, 54838, 54327, 53821, 53319, 52822, 52329, 51841, 51358, 50879, 50405, 49935, 49469, 49008, 48551,
	48099, 47650, 47206, 46766, 46330, 45898, 45470, 45046, 44626, 44210, 43798, 43389, 42985, 42584, 42187, 41794, 41404, 41018, 40636, 40257, 39882, 39510, 39141, 38776, 38415,
	38057, 37702, 37350, 37002, 36657, 36315, 35977, 35641, 35309, 34980, 34654, 34331, 34011, 33694, 33379, 33068, 32760, 32455, 32152, 31852, 31555, 31261, 30970, 30681, 30395,
	30111, 29831, 29553, 29277, 29004, 28734, 28466, 28200, 27937, 27677, 27419, 27163, 26910, 26659, 26411, 26164, 25920, 25679, 25439, 25202, 24967, 24734, 24504, 24275, 24049,
	23825, 23603, 23383, 23165, 22949, 22735, 22523, 22313, 22105, 21899, 21694, 21492, 21292, 21093, 20897, 20702, 20509, 20318, 20128, 19941, 19755, 19570, 19388, 19207, 19028,
	18851, 18675, 18501, 18328, 18157, 17988, 17820, 17654, 17490, 17327, 17165, 17005, 16847, 16689, 16534, 16380, 16227, 16076, 15926, 15777, 15630, 15485, 15340, 15197, 15055,
	14915, 14776, 14638, 14502, 14367, 14233, 14100, 13968, 13838, 13709, 13581, 13455, 13329, 13205, 13082, 12960, 12839, 12719, 12601, 12483, 12367, 12252, 12137, 12024, 11912,
	11801, 11691, 11582, 11474, 11367, 11261, 11156, 11052, 10949, 10847, 10746, 10646, 10546, 10448, 10351, 10254, 10159, 10064, 9970, 9877, 9785, 9694, 9603, 9514, 9425,
	9337, 9250, 9164, 9078, 8994, 8910, 8827, 8745, 8663, 8582, 8502, 8423, 8344, 8267, 8190, 8113, 8038, 7963, 7888, 7815, 7742, 7670, 7598, 7527, 7457,
	7388, 7319, 7251, 7183, 7116, 7050, 6984, 6919, 6854, 6790, 6727, 6664, 6602, 6541, 6480, 6419, 6359, 6300, 6241, 6183, 6126, 6068, 6012, 5956, 5900,
	5845, 5791, 5737, 5683, 5630, 5578, 5526, 5474, 5423, 5373, 5323, 5273, 5224, 5175, 5127, 5079, 5032, 4985, 4938, 4892, 4847, 4801, 4757, 4712, 4668,
	4625, 4582, 4539, 4497, 4455, 4413, 4372, 4331, 4291, 4251, 4211, 4172, 4133, 4095, 4056, 4019, 3981, 3944, 3907, 3871, 3835, 3799, 3763, 3728, 3694,
	3659, 3625, 3591, 3558, 3525, 3492, 3459, 3427, 3395, 3363, 3332, 3301, 3270, 3240, 3209, 3179, 3150, 3120, 3091, 3063, 3034, 3006, 2978, 2950, 2922,
	2895, 2868, 2841, 2815, 2789, 2763, 2737, 2711, 2686, 2661, 2636, 2612, 2587, 2563, 2539, 2516, 2492, 2469, 2446, 2423, 2400, 2378, 2356, 2334, 2312,
	2291, 2269, 2248, 2227, 2206, 2186, 2165, 2145, 2125, 2105, 2086, 2066, 2047, 2028, 2009, 1990, 1972, 1953, 1935, 1917, 1899, 1881, 1864, 1847, 1829,
	1812, 1795, 1779, 1762, 1746, 1729, 1713, 1697, 1681, 1666, 1650, 1635, 1620, 1604, 1589, 1575, 1560, 1545, 1531, 1517, 1503, 1489, 1475, 1461, 1447,
	1434, 1420, 1407, 1394, 1381, 1368, 1355, 1343, 1330, 1318, 1306, 1293, 1281, 1269, 1258, 1246, 1234, 1223, 1211, 1200, 1189, 1178, 1167, 1156, 1145,
	1134, 1124, 1113, 1103, 1093, 1082, 1072, 1062, 1052, 1043, 1033, 1023, 1014, 1004, 995, 986, 976, 967, 958, 949, 940, 932, 923, 914, 906,
	897, 889, 881, 873, 864, 856, 848, 840, 833, 825, 817, 810, 802, 794, 787, 780, 772, 765, 758, 751, 744, 737, 730, 723, 717,
	710, 703, 697, 690, 684, 677, 671, 665, 659, 653, 646, 640, 634, 629, 623, 617, 611, 605, 600, 594, 589, 583, 578, 572, 567,
	562, 556, 551, 546, 541, 536, 531, 526, 521, 516, 511, 507, 502, 497, 493, 488, 483, 479, 474, 470, 466, 461, 457, 453, 448,
	444, 440, 436, 432, 428, 424, 420, 416, 412, 408, 405, 401, 397, 393, 390, 386, 382, 379, 375, 372, 368, 365, 361, 358, 355,
	351, 348, 345, 342, 338, 335, 332, 329, 326, 323, 320, 317, 314, 311, 308, 305, 302, 300, 297, 294, 291, 289, 286, 283, 281,
	278, 275, 273, 270, 268, 265, 263, 260, 258, 255, 253, 251, 248, 246, 244, 241, 239, 237, 235, 233, 230, 228, 226, 224, 222,
	220, 218, 216, 214, 212, 210, 208, 206, 204, 202, 200, 198, 196, 195, 193, 191, 189, 187, 186, 184, 182, 180, 179, 177, 175,
	174, 172, 171, 169, 167, 166, 164, 163, 161, 160, 158, 157, 155, 154, 152, 151, 150, 148, 147, 145, 144, 143, 141, 140, 139,
	137, 136, 135, 134, 132, 131, 130, 129, 127, 126, 125, 124, 123, 122, 120, 119, 118, 117, 116, 115, 114, 113, 112, 111, 110,
	109, 108, 107, 106, 105, 104, 103, 102, 101, 100, 99, 98, 97, 96, 95, 94, 93, 93, 92, 91, 90, 89, 88, 87, 87,
	86, 85, 84, 83, 83, 82, 81, 80, 80, 79, 78, 77, 77, 76, 75, 75, 74, 73, 72, 72, 71, 70, 70, 69, 68,
	68, 67, 67, 66, 65, 65, 64, 63, 63, 62, 62, 61, 61, 60, 59, 59, 58, 58, 57, 57, 56, 56, 55, 55, 54,
	54, 53, 53, 52, 52, 51, 51, 50, 50, 49, 49, 48, 48, 47, 47, 46, 46, 46, 45, 45, 44, 44, 43, 43, 43,
	42, 42, 41, 41, 41, 40, 40, 40, 39, 39, 38, 38, 38, 37, 37, 37, 36, 36, 36, 35, 35, 35, 34, 34, 34,
	33, 33, 33, 32, 32, 32, 31, 31, 31, 31, 30, 30, 30, 29, 29, 29, 29, 28, 28, 28, 28, 27, 27, 27, 27,
	26, 26, 26, 26, 25, 25, 25, 25, 24, 24, 24, 24, 23, 23, 23, 23, 23, 22, 22, 22, 22, 21, 21, 21, 21,
	21, 20, 20, 20, 20, 20, 20, 19, 19, 19, 19, 19, 18, 18, 18, 18, 18, 18, 17, 17, 17, 17, 17, 17, 16,
	16, 16, 16, 16, 16, 15, 15, 15, 15, 15, 15, 15, 14, 14, 14, 14, 14, 14, 14, 14, 13, 13, 13, 13, 13,
	13, 13, 13, 12, 12, 12, 12, 12, 12, 12, 12, 11, 11, 11, 11, 11, 11, 11, 11, 11, 10, 10, 10, 10, 10,
	10, 10, 10, 10, 10, 10, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 8, 8, 8, 8, 8, 8, 8, 8,
	8, 8, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
	5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 0,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MAINNET_PARAMS;
    use sophis_consensus_core::{
        config::params::{ForkActivation, Params, SIMNET_PARAMS},
        constants::SOMPI_PER_SOPHIS,
        network::{NetworkId, NetworkType},
        tx::scriptvec,
    };

    #[test]
    fn calc_high_bps_total_rewards_delta() {
        let legacy_cbm = create_legacy_manager();
        let pre_deflationary_rewards = legacy_cbm.pre_deflationary_phase_base_subsidy * legacy_cbm.deflationary_phase_daa_score;
        let total_rewards: u64 = pre_deflationary_rewards + SUBSIDY_BY_MONTH_TABLE.iter().map(|x| x * SECONDS_PER_MONTH).sum::<u64>();
        let testnet_11_bps = SIMNET_PARAMS.bps();
        let total_high_bps_rewards_rounded_up: u64 = pre_deflationary_rewards
            + SUBSIDY_BY_MONTH_TABLE.iter().map(|x| (x.div_ceil(testnet_11_bps) * testnet_11_bps) * SECONDS_PER_MONTH).sum::<u64>();

        let cbm = create_manager(&SIMNET_PARAMS);
        let total_high_bps_rewards: u64 = pre_deflationary_rewards
            + cbm.subsidy_by_month_table_before.iter().map(|x| x * SECONDS_PER_MONTH * cbm.bps().before()).sum::<u64>();
        assert_eq!(total_high_bps_rewards_rounded_up, total_high_bps_rewards, "subsidy adjusted to bps must be rounded up");

        let delta = total_high_bps_rewards as i64 - total_rewards as i64;

        println!("Total rewards: {} sompi => {} SPHS", total_rewards, total_rewards / SOMPI_PER_SOPHIS);
        println!("Total high bps rewards: {} sompi => {} SPHS", total_high_bps_rewards, total_high_bps_rewards / SOMPI_PER_SOPHIS);
        println!("Delta: {} sompi => {} SPHS", delta, delta / SOMPI_PER_SOPHIS as i64);
    }

    #[test]
    fn subsidy_by_month_table_test() {
        let cbm = create_legacy_manager();
        cbm.subsidy_by_month_table_before.iter().enumerate().for_each(|(i, x)| {
            assert_eq!(SUBSIDY_BY_MONTH_TABLE[i], *x, "for 1 BPS, const table and precomputed values must match");
        });

        for network_id in NetworkId::iter() {
            let cbm = create_manager(&network_id.into());
            cbm.subsidy_by_month_table_before.iter().enumerate().for_each(|(i, x)| {
                assert_eq!(
                    SUBSIDY_BY_MONTH_TABLE[i].div_ceil(cbm.bps().before()),
                    *x,
                    "{}: locally computed and precomputed values must match",
                    network_id
                );
            });
            cbm.subsidy_by_month_table_after.iter().enumerate().for_each(|(i, x)| {
                assert_eq!(
                    SUBSIDY_BY_MONTH_TABLE[i].div_ceil(cbm.bps().after()),
                    *x,
                    "{}: locally computed and precomputed values must match",
                    network_id
                );
            });
        }
    }

    /// Takes over 60 seconds, run with the following command line:
    /// `cargo test --release --package sophis-consensus --lib -- processes::coinbase::tests::verify_crescendo_emission_schedule --exact --nocapture --ignored`
    #[test]
    #[ignore = "long"]
    fn verify_crescendo_emission_schedule() {
        // No need to loop over all nets since the relevant params are only
        // deflation and activation DAA scores (and the test is long anyway)
        for network_id in [NetworkId::new(NetworkType::Mainnet)] {
            let mut params: Params = network_id.into();
            params.crescendo_activation = ForkActivation::never();
            let cbm = create_manager(&params);
            let (baseline_epochs, baseline_total) = calculate_emission(cbm);

            let mut activations = vec![10000, 33444444, 120727479];
            for network_id in NetworkId::iter() {
                let activation = Params::from(network_id).crescendo_activation;
                if activation != ForkActivation::never() && activation != ForkActivation::always() {
                    activations.push(activation.daa_score());
                }
            }

            // Loop over a few random activation points + specified activation points for all nets
            for activation in activations {
                params.crescendo_activation = ForkActivation::new(activation);
                let cbm = create_manager(&params);
                let (new_epochs, new_total) = calculate_emission(cbm);

                // Epochs only represents the number of times the subsidy changed (lower after activation due to rounding)
                println!("BASELINE:\t{}\tepochs, total emission: {}", baseline_epochs, baseline_total);
                println!("CRESCENDO:\t{}\tepochs, total emission: {}, activation: {}", new_epochs, new_total, activation);

                let diff = (new_total as i64 - baseline_total as i64) / SOMPI_PER_SOPHIS as i64;
                assert!(diff.abs() <= 51, "activation: {}", activation);
                println!("DIFF (SPHS): {}", diff);
            }
        }
    }

    fn calculate_emission(cbm: CoinbaseManager) -> (u64, u64) {
        let activation = cbm.bps().activation().daa_score();
        let mut current = 0;
        let mut total = 0;
        let mut epoch = 0u64;
        let mut prev = cbm.calc_block_subsidy(0);
        loop {
            let subsidy = cbm.calc_block_subsidy(current);
            // Pre activation we expect the legacy calc (1bps)
            if current < activation {
                assert_eq!(cbm.legacy_calc_block_subsidy(current), subsidy);
            }
            if subsidy == 0 {
                break;
            }
            total += subsidy;
            if subsidy != prev {
                println!("epoch: {}, subsidy: {}", epoch, subsidy);
                prev = subsidy;
                epoch += 1;
            }
            current += 1;
        }

        (epoch, total)
    }

    #[test]
    fn subsidy_test() {
        const DEFLATIONARY_PHASE_INITIAL_SUBSIDY: u64 = 54_089_972;
        const SECONDS_PER_MONTH: u64 = 2629800;
        const SECONDS_PER_HALVING: u64 = SECONDS_PER_MONTH * 74;

        for network_id in NetworkId::iter() {
            let mut params: Params = network_id.into();
            if params.crescendo_activation != ForkActivation::always() {
                // We test activation scenarios in verify_crescendo_emission_schedule
                params.crescendo_activation = ForkActivation::never();
            }
            let cbm = create_manager(&params);
            let bps = params.bps_history().before();

            // Use the network-specific value from params; simnet uses a different formula than mainnet/testnet
            let pre_deflationary_phase_base_subsidy = params.pre_deflationary_phase_base_subsidy;
            let deflationary_phase_initial_subsidy = DEFLATIONARY_PHASE_INITIAL_SUBSIDY.div_ceil(bps);
            let blocks_per_halving = SECONDS_PER_HALVING * bps;

            struct Test {
                name: &'static str,
                daa_score: u64,
                expected: u64,
            }

            let mut tests = vec![
                Test {
                    name: "first mined block",
                    daa_score: 1,
                    expected: if params.deflationary_phase_daa_score > 0 {
                        pre_deflationary_phase_base_subsidy
                    } else {
                        deflationary_phase_initial_subsidy
                    },
                },
                Test {
                    name: "start of deflationary phase",
                    daa_score: params.deflationary_phase_daa_score,
                    expected: deflationary_phase_initial_subsidy,
                },
                Test {
                    name: "after one halving",
                    daa_score: params.deflationary_phase_daa_score + blocks_per_halving,
                    expected: (DEFLATIONARY_PHASE_INITIAL_SUBSIDY / 2).div_ceil(bps),
                },
                Test {
                    name: "after 2 halvings",
                    daa_score: params.deflationary_phase_daa_score + 2 * blocks_per_halving,
                    expected: (DEFLATIONARY_PHASE_INITIAL_SUBSIDY / 4).div_ceil(bps),
                },
                Test {
                    name: "after 5 halvings",
                    daa_score: params.deflationary_phase_daa_score + 5 * blocks_per_halving,
                    expected: (DEFLATIONARY_PHASE_INITIAL_SUBSIDY / 32).div_ceil(bps),
                },
                Test {
                    name: "after 32 halvings",
                    daa_score: params.deflationary_phase_daa_score + 32 * blocks_per_halving,
                    expected: (DEFLATIONARY_PHASE_INITIAL_SUBSIDY / 2_u64.pow(32)).div_ceil(bps),
                },
                Test {
                    name: "just before subsidy depleted",
                    daa_score: params.deflationary_phase_daa_score + 25 * blocks_per_halving,
                    expected: 1,
                },
                Test {
                    name: "after subsidy depleted",
                    daa_score: params.deflationary_phase_daa_score + 26 * blocks_per_halving,
                    expected: 0,
                },
            ];

            if params.deflationary_phase_daa_score > 0 {
                tests.push(Test {
                    name: "before deflationary phase",
                    daa_score: params.deflationary_phase_daa_score - 1,
                    expected: pre_deflationary_phase_base_subsidy,
                });
            }

            for t in tests {
                assert_eq!(cbm.calc_block_subsidy(t.daa_score), t.expected, "{} test '{}' failed", network_id, t.name);
                if bps == 1 {
                    assert_eq!(cbm.legacy_calc_block_subsidy(t.daa_score), t.expected, "{} test '{}' failed", network_id, t.name);
                }
            }
        }
    }

    #[test]
    fn payload_serialization_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3];
        let data = CoinbaseData {
            blue_score: 56,
            subsidy: 44000000000,
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data as &[u8],
            },
        };

        let payload = cbm.serialize_coinbase_payload(&data).unwrap();
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data, deserialized_data);

        // Test an actual mainnet payload
        let payload_hex =
            "b612c90100000000041a763e07000000000022202b32443ff740012157716d81216d09aebc39e5493c93a7181d92cb756c02c560ac302e31322e382f";
        let mut payload = vec![0u8; payload_hex.len() / 2];
        faster_hex::hex_decode(payload_hex.as_bytes(), &mut payload).unwrap();
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        let expected_data = CoinbaseData {
            blue_score: 29954742,
            subsidy: 31112698372,
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(
                    0,
                    scriptvec![
                        32, 43, 50, 68, 63, 247, 64, 1, 33, 87, 113, 109, 129, 33, 109, 9, 174, 188, 57, 229, 73, 60, 147, 167, 24,
                        29, 146, 203, 117, 108, 2, 197, 96, 172,
                    ],
                ),
                extra_data: &[48u8, 46, 49, 50, 46, 56, 47] as &[u8],
            },
        };
        assert_eq!(expected_data, deserialized_data);
    }

    #[test]
    fn modify_payload_test() {
        let cbm = create_manager(&MAINNET_PARAMS);

        let script_data = [33u8, 255];
        let extra_data = [2u8, 3, 23, 98];
        let data = CoinbaseData {
            blue_score: 56345,
            subsidy: 44000000000,
            miner_data: MinerData {
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&script_data)),
                extra_data: &extra_data,
            },
        };

        let data2 = CoinbaseData {
            blue_score: data.blue_score,
            subsidy: data.subsidy,
            miner_data: MinerData {
                // Modify only miner data
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[33u8, 255, 33])),
                extra_data: &[2u8, 3, 23, 98, 34, 34] as &[u8],
            },
        };

        let mut payload = cbm.serialize_coinbase_payload(&data).unwrap();
        payload = cbm.modify_coinbase_payload(payload, &data2.miner_data).unwrap(); // Update the payload with the modified miner data
        let deserialized_data = cbm.deserialize_coinbase_payload(&payload).unwrap();

        assert_eq!(data2, deserialized_data);
    }

    fn create_manager(params: &Params) -> CoinbaseManager {
        CoinbaseManager::new(
            params.coinbase_payload_script_public_key_max_len,
            params.max_coinbase_payload_len,
            params.deflationary_phase_daa_score,
            params.pre_deflationary_phase_base_subsidy,
            params.bps_history(),
        )
    }

    /// Return a CoinbaseManager with legacy golang 1 BPS properties
    fn create_legacy_manager() -> CoinbaseManager {
        CoinbaseManager::new(150, 204, 15778800 - 259200, 370_027_857, ForkedParam::new_const(1))
    }
}
