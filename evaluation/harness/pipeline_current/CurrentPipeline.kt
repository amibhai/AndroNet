package com.andronet.eval

import com.example.packet_analyzer.AnomalyDetector
import com.example.packet_analyzer.DomainTracker
import com.example.packet_analyzer.PacketPipeline
import com.example.packet_analyzer.PacketRecord
import com.example.packet_analyzer.RuleEngine
import com.example.packet_analyzer.TrafficStatistics

/** The working tree's own record builder and pipeline, with nothing copied. */
object Pipeline {
    const val NAME = "current"

    fun reset() {
        AnomalyDetector.reset()
        RuleEngine.clearState()
        AnomalyDetector.adaptiveThresholds.reset()
        DomainTracker.clear()
        TrafficStatistics.reset()
    }

    /** view "vpn": what a TUN device can carry. view "root": everything an interface tap sees. */
    fun buildRecord(unit: NetUnit, outgoing: Boolean, view: String): Map<String, Any>? = when (unit) {
        is NetUnit.Ip -> PacketRecord.fromIpPacket(unit.packet, outgoing, if (view == "root") PacketRecord.MODE_ROOT else PacketRecord.MODE_VPN)
        is NetUnit.Arp -> if (view == "root") {
            PacketRecord.fromArp(unit.senderMac, unit.senderIp, unit.targetIp, unit.raw.size, outgoing, PacketRecord.MODE_ROOT)
        } else {
            null
        }
    }

    fun rawOf(unit: NetUnit): ByteArray? = (unit as? NetUnit.Ip)?.packet

    fun dissectAndEnrich(record: Map<String, Any>, raw: ByteArray?) = PacketPipeline.dissectAndEnrich(record, raw)

    fun analyze(finalPacket: MutableMap<String, Any>, payload: ByteArray?) = PacketPipeline.analyze(finalPacket, payload)
}
