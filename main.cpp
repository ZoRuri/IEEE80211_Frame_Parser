#include <QCoreApplication>
#include <QDebug>

#include <arpa/inet.h>
#include <pcap.h>
#include <ieee80211.h>

#define RADIOTAPLEN *(data + 2)

void IEEE80211_Frame_Parser(const u_char *data);
void IEEE80211_MGT_Frame(const u_char *data, ieee80211_frame *fdh);
void IEEE80211_CTL_Frame(const u_char *data, ieee80211_frame *fdh);
void IEEE80211_DATA_Frame(const u_char *data, ieee80211_frame *fdh);

ieee80211_frame *IEEE80211_DS_ADDR(const u_char *data);

QString MacADDR(u_int8_t* ADDR);

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    const char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    dev = "wlan4";
    pcap_t *handle;
    struct pcap_pkthdr *pkthdr;
    const u_char *data;

    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

    while(true)
    {
        pcap_next_ex(handle, &pkthdr, &data);

        IEEE80211_Frame_Parser(data);
    }
}

void IEEE80211_Frame_Parser(const u_char *data) {
    int radiotapLen = *(data + 2);

    /* Distribute System (DS) */
    ieee80211_frame *fdh = IEEE80211_DS_ADDR(data);

    /* Frame Control Field */
    switch(fdh->i_fc[0] & IEEE80211_FC0_TYPE_MASK)  /* Frame Type */
    {
        case IEEE80211_FC0_TYPE_MGT:    /* Management Frame */
            qDebug() << "Management";
            IEEE80211_MGT_Frame(data, fdh);
            break;

        case IEEE80211_FC0_TYPE_CTL:    /* Control Frame */
            qDebug() << "Control";
            IEEE80211_CTL_Frame(data, fdh);
            break;

        case IEEE80211_FC0_TYPE_DATA:   /* Data Frame */
            qDebug() << "Data";
            IEEE80211_DATA_Frame(data, fdh);
            break;

        default:
            break;
    }
}

void IEEE80211_MGT_Frame(const u_char *data, ieee80211_frame *fdh) {
    /* Management Frame Subtype */
    switch(fdh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
    {
        case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
            break;

        case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
            break;

        case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
            break;

        case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
            break;

        case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
            break;

        case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
            break;

        case IEEE80211_FC0_SUBTYPE_BEACON:
            break;

        case IEEE80211_FC0_SUBTYPE_ATIM:
            break;

        case IEEE80211_FC0_SUBTYPE_DISASSOC:
            break;

        case IEEE80211_FC0_SUBTYPE_AUTH:
            break;

        case IEEE80211_FC0_SUBTYPE_DEAUTH:
            break;

        case IEEE80211_FC0_SUBTYPE_ACTION:
            break;

        case IEEE80211_FC0_SUBTYPE_ACTION_NOACK:
            break;
    }

    int datapoint = *(data + 2) + sizeof(*fdh); /* radiotap length + frame lenth */

    /* Fixed parameters (12 bytes) */

    qDebug() << "Timestamp:" << hex << *((u_int64_t*)(data + datapoint));
    qDebug() << "Beacon Interval:" << IEEE80211_BEACON_INTERVAL(data + datapoint) * 1.024 << "ms";

    /* Capabilities Information */

    switch (IEEE80211_BEACON_CAPABILITY(data + datapoint) & 0xFFFF)
    {
        case IEEE80211_CAPINFO_ESS:
            break;

        case IEEE80211_CAPINFO_IBSS:
            break;

        case IEEE80211_CAPINFO_CF_POLLABLE:
            break;

        case IEEE80211_CAPINFO_CF_POLLREQ:
            break;

        case IEEE80211_CAPINFO_PRIVACY:         /* WEP */
            break;

        case IEEE80211_CAPINFO_SHORT_PREAMBLE:
            break;

        case IEEE80211_CAPINFO_PBCC:
            break;

        case IEEE80211_CAPINFO_CHNL_AGILITY:
            break;

        case IEEE80211_CAPINFO_SPECTRUM_MGMT:
            break;

        case IEEE80211_CAPINFO_SHORT_SLOTTIME:
            break;

        case IEEE80211_CAPINFO_RSN:
            break;

        case IEEE80211_CAPINFO_DSSSOFDM:
            break;

        default:
            break;
    }

    /* tagged parameters */

}

void IEEE80211_CTL_Frame(const u_char *data, ieee80211_frame *fdh) {
    /* Control Frame Subtype */
    switch(fdh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
    {
        case IEEE80211_FC0_SUBTYPE_BAR:
            break;

        case IEEE80211_FC0_SUBTYPE_BA:
            break;

        case IEEE80211_FC0_SUBTYPE_PS_POLL:
            break;

        case IEEE80211_FC0_SUBTYPE_RTS:
            break;

        case IEEE80211_FC0_SUBTYPE_CTS:
            break;

        case IEEE80211_FC0_SUBTYPE_ACK:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_END:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_END_ACK:
            break;
    }
}

void IEEE80211_DATA_Frame(const u_char *data, ieee80211_frame *fdh) {
    /* Data Frame Subtype */
    switch(fdh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
    {
        case IEEE80211_FC0_SUBTYPE_DATA:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_ACK:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_POLL:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_ACPL:
            break;

        case IEEE80211_FC0_SUBTYPE_NODATA:
            break;

        case IEEE80211_FC0_SUBTYPE_CFACK:
            break;

        case IEEE80211_FC0_SUBTYPE_CFPOLL:
            break;

        case IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK:
            break;

        case IEEE80211_FC0_SUBTYPE_QOS:
            break;

        case IEEE80211_FC0_SUBTYPE_QOS_NULL:
            break;
    }
}

ieee80211_frame *IEEE80211_DS_ADDR(const u_char *data) {
    /*frames struct*/
    ieee80211_frame *fdh = (struct ieee80211_frame *)(data + RADIOTAPLEN);

    /*
     *  Data Frame - Address field contents
     *
     *  To Ds  | From DS | Addr 1 | Addr 2 | Addr 3 | Addr 4
     *    0    |  0      |  DA    | SA     | BSSID  | n/a
     *    0    |  1      |  DA    | BSSID  | SA     | n/a
     *    1    |  0      |  BSSID | SA     | DA     | n/a
     *    1    |  1      |  RA    | TA     | DA     | SA
     */

    switch(fdh->i_fc[1] & IEEE80211_FC1_DIR_MASK)    /* Distribute System (DS) */
    {
        case IEEE80211_FC1_DIR_NODS:    /* STA -> STA */
            qDebug() << "DA:" << MacADDR(fdh->i_addr1);
            qDebug() << "SA:" << MacADDR(fdh->i_addr2);
            qDebug() << "BSSID:" << MacADDR(fdh->i_addr3);
            break;

        case IEEE80211_FC1_DIR_TODS:    /* STA -> AP */
            qDebug() << "DA:" << MacADDR(fdh->i_addr3);
            qDebug() << "SA:" << MacADDR(fdh->i_addr2);
            qDebug() << "BSSID:" << MacADDR(fdh->i_addr1);
            break;

        case IEEE80211_FC1_DIR_FROMDS:  /* AP -> STA */
            qDebug() << "DA:" << MacADDR(fdh->i_addr1);
            qDebug() << "SA:" << MacADDR(fdh->i_addr3);
            qDebug() << "BSSID:" << MacADDR(fdh->i_addr2);
            break;

        case IEEE80211_FC1_DIR_DSTODS:  /* AP -> AP */
            ieee80211_frame_addr4 *fdh = (struct ieee80211_frame_addr4 *)(data + RADIOTAPLEN);
            qDebug() << "RA:" << MacADDR(fdh->i_addr1);
            qDebug() << "TA:" << MacADDR(fdh->i_addr2);
            qDebug() << "DA:" << MacADDR(fdh->i_addr3);
            qDebug() << "SA:" << MacADDR(fdh->i_addr4);
            break;
    }

    return fdh;
}

QString MacADDR(u_int8_t* ADDR) {
    QString MacADDR;

    MacADDR.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", ADDR[0], ADDR[1], ADDR[2], ADDR[3], ADDR[4], ADDR[5]);

    return MacADDR;
}
