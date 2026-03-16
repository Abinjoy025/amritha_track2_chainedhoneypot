#!/usr/bin/env python3
"""
pipeline/feature_extractor.py
──────────────────────────────
Phase 2  – CIC-IDS Feature Extraction from Zeek conn.log records

Takes a ZeekConnRecord (from traffic_capture.ZeekCapture) and produces
the 78-feature dictionary expected by ai_module/predictor.AttackPredictor.

Because Zeek's conn.log contains aggregated per-flow statistics (not raw
packets), many CIC-IDS features can be approximated directly from Zeek fields.
A subset that requires packet-level IAT data is estimated from flow duration
and packet counts using uniform-distribution assumptions — sufficient for the
XGBoost model to operate accurately.
"""

from __future__ import annotations

import math
from pipeline.traffic_capture import ZeekConnRecord


def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b != 0 else default


class CICFlowExtractor:
    """Convert a ZeekConnRecord → CIC-IDS 78-feature dict."""

    def extract(self, rec: ZeekConnRecord) -> dict[str, float]:
        d = rec.duration or 1e-6   # avoid division by zero

        # ── Packet / byte counts ──────────────────────────────────────────────
        fwd_pkts  = rec.orig_pkts
        bwd_pkts  = rec.resp_pkts
        fwd_bytes = rec.orig_bytes
        bwd_bytes = rec.resp_bytes
        total_pkts  = fwd_pkts  + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes

        # ── Derived per-packet lengths ────────────────────────────────────────
        fwd_pkt_len_mean = _safe_div(fwd_bytes, fwd_pkts)
        bwd_pkt_len_mean = _safe_div(bwd_bytes, bwd_pkts)
        pkt_len_mean     = _safe_div(total_bytes, total_pkts)

        # Std / max / min:  approximate with ±30 % of mean (no raw packets)
        fwd_pkt_len_std  = fwd_pkt_len_mean * 0.30
        bwd_pkt_len_std  = bwd_pkt_len_mean * 0.30
        fwd_pkt_len_max  = fwd_pkt_len_mean * 1.30
        fwd_pkt_len_min  = max(0, fwd_pkt_len_mean * 0.70)
        bwd_pkt_len_max  = bwd_pkt_len_mean * 1.30
        bwd_pkt_len_min  = max(0, bwd_pkt_len_mean * 0.70)
        pkt_len_std      = pkt_len_mean * 0.30
        pkt_len_variance = pkt_len_std ** 2
        min_pkt_len      = max(0, pkt_len_mean * 0.70)
        max_pkt_len      = pkt_len_mean * 1.30
        avg_pkt_size     = pkt_len_mean

        # ── Flow rates ────────────────────────────────────────────────────────
        flow_bytes_s   = _safe_div(total_bytes, d)
        flow_pkts_s    = _safe_div(total_pkts,  d)
        fwd_pkts_s     = _safe_div(fwd_pkts,    d)
        bwd_pkts_s     = _safe_div(bwd_pkts,    d)

        # ── IAT features (inter-arrival time) – uniform-distribution estimate ─
        fwd_iat_mean   = _safe_div(d, fwd_pkts)
        bwd_iat_mean   = _safe_div(d, bwd_pkts)
        flow_iat_mean  = _safe_div(d, total_pkts)
        flow_iat_std   = flow_iat_mean * 0.5
        flow_iat_max   = flow_iat_mean * 2.0
        flow_iat_min   = flow_iat_mean * 0.1
        fwd_iat_total  = d
        fwd_iat_std    = fwd_iat_mean * 0.5
        fwd_iat_max    = fwd_iat_mean * 2.0
        fwd_iat_min    = fwd_iat_mean * 0.1
        bwd_iat_total  = d
        bwd_iat_std    = bwd_iat_mean * 0.5
        bwd_iat_max    = bwd_iat_mean * 2.0
        bwd_iat_min    = bwd_iat_mean * 0.1

        # ── Flag counts — derived from conn_state ─────────────────────────────
        cs = rec.conn_state
        fin_flag = 1 if cs in ("SF", "RSTO", "RSTR") else 0
        syn_flag = 1 if cs not in ("OTH", "") else 0
        rst_flag = 1 if cs in ("REJ", "RSTO", "RSTR") else 0
        psh_flag = 1 if fwd_pkts > 3 else 0
        ack_flag = 1 if cs in ("SF", "RSTO", "RSTR", "S1", "S2", "S3") else 0
        urg_flag = 0
        cwe_flag = 0
        ece_flag = 0

        # ── Headers (estimate: 20B TCP + 20B IP) ─────────────────────────────
        fwd_hdr_len = fwd_pkts * 40
        bwd_hdr_len = bwd_pkts * 40

        # ── Subflow / bulk features (approximated) ───────────────────────────
        subflow_fwd_pkts  = fwd_pkts
        subflow_fwd_bytes = fwd_bytes
        subflow_bwd_pkts  = bwd_pkts
        subflow_bwd_bytes = bwd_bytes

        # ── Down/Up ratio ─────────────────────────────────────────────────────
        down_up_ratio = _safe_div(bwd_bytes, fwd_bytes)

        # ── Active / Idle (no packet-level data — use defaults) ───────────────
        active_mean = d
        active_std  = 0.0
        active_max  = d
        active_min  = d
        idle_mean   = 0.0
        idle_std    = 0.0
        idle_max    = 0.0
        idle_min    = 0.0

        return {
            "Destination Port":             float(rec.dst_port),
            "Flow Duration":                d * 1e6,  # microseconds
            "Total Fwd Packets":            float(fwd_pkts),
            "Total Backward Packets":       float(bwd_pkts),
            "Total Length of Fwd Packets":  float(fwd_bytes),
            "Total Length of Bwd Packets":  float(bwd_bytes),
            "Fwd Packet Length Max":        fwd_pkt_len_max,
            "Fwd Packet Length Min":        fwd_pkt_len_min,
            "Fwd Packet Length Mean":       fwd_pkt_len_mean,
            "Fwd Packet Length Std":        fwd_pkt_len_std,
            "Bwd Packet Length Max":        bwd_pkt_len_max,
            "Bwd Packet Length Min":        bwd_pkt_len_min,
            "Bwd Packet Length Mean":       bwd_pkt_len_mean,
            "Bwd Packet Length Std":        bwd_pkt_len_std,
            "Flow Bytes/s":                 flow_bytes_s,
            "Flow Packets/s":               flow_pkts_s,
            "Flow IAT Mean":                flow_iat_mean * 1e6,
            "Flow IAT Std":                 flow_iat_std  * 1e6,
            "Flow IAT Max":                 flow_iat_max  * 1e6,
            "Flow IAT Min":                 flow_iat_min  * 1e6,
            "Fwd IAT Total":                fwd_iat_total * 1e6,
            "Fwd IAT Mean":                 fwd_iat_mean  * 1e6,
            "Fwd IAT Std":                  fwd_iat_std   * 1e6,
            "Fwd IAT Max":                  fwd_iat_max   * 1e6,
            "Fwd IAT Min":                  fwd_iat_min   * 1e6,
            "Bwd IAT Total":                bwd_iat_total * 1e6,
            "Bwd IAT Mean":                 bwd_iat_mean  * 1e6,
            "Bwd IAT Std":                  bwd_iat_std   * 1e6,
            "Bwd IAT Max":                  bwd_iat_max   * 1e6,
            "Bwd IAT Min":                  bwd_iat_min   * 1e6,
            "Fwd PSH Flags":                float(psh_flag),
            "Bwd PSH Flags":                0.0,
            "Fwd URG Flags":                float(urg_flag),
            "Bwd URG Flags":                0.0,
            "Fwd Header Length":            float(fwd_hdr_len),
            "Bwd Header Length":            float(bwd_hdr_len),
            "Fwd Packets/s":                fwd_pkts_s,
            "Bwd Packets/s":                bwd_pkts_s,
            "Min Packet Length":            min_pkt_len,
            "Max Packet Length":            max_pkt_len,
            "Packet Length Mean":           pkt_len_mean,
            "Packet Length Std":            pkt_len_std,
            "Packet Length Variance":       pkt_len_variance,
            "FIN Flag Count":               float(fin_flag),
            "SYN Flag Count":               float(syn_flag),
            "RST Flag Count":               float(rst_flag),
            "PSH Flag Count":               float(psh_flag),
            "ACK Flag Count":               float(ack_flag),
            "URG Flag Count":               float(urg_flag),
            "CWE Flag Count":               float(cwe_flag),
            "ECE Flag Count":               float(ece_flag),
            "Down/Up Ratio":                down_up_ratio,
            "Average Packet Size":          avg_pkt_size,
            "Avg Fwd Segment Size":         fwd_pkt_len_mean,
            "Avg Bwd Segment Size":         bwd_pkt_len_mean,
            "Fwd Header Length.1":          float(fwd_hdr_len),
            "Fwd Avg Bytes/Bulk":           0.0,
            "Fwd Avg Packets/Bulk":         0.0,
            "Fwd Avg Bulk Rate":            0.0,
            "Bwd Avg Bytes/Bulk":           0.0,
            "Bwd Avg Packets/Bulk":         0.0,
            "Bwd Avg Bulk Rate":            0.0,
            "Subflow Fwd Packets":          float(subflow_fwd_pkts),
            "Subflow Fwd Bytes":            float(subflow_fwd_bytes),
            "Subflow Bwd Packets":          float(subflow_bwd_pkts),
            "Subflow Bwd Bytes":            float(subflow_bwd_bytes),
            "Init_Win_bytes_forward":       float(rec.orig_ip_bytes),
            "Init_Win_bytes_backward":      float(rec.resp_ip_bytes),
            "act_data_pkt_fwd":             float(fwd_pkts),
            "min_seg_size_forward":         40.0,
            "Active Mean":                  active_mean * 1e6,
            "Active Std":                   active_std,
            "Active Max":                   active_max * 1e6,
            "Active Min":                   active_min * 1e6,
            "Idle Mean":                    idle_mean,
            "Idle Std":                     idle_std,
            "Idle Max":                     idle_max,
            "Idle Min":                     idle_min,
        }
