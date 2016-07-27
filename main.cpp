#include <QCoreApplication>
#include <QDebug>

#include <arpa/inet.h>
#include <pcap.h>
#include <ieee80211.h>

#define RADIOTAPLEN *(data + 2)

void IEEE80211_Frame_Parser(const u_char *data, pcap_pkthdr *pkthdr);

void IEEE80211_MGT_Frame(const u_char *data, ieee80211_frame *fdh, pcap_pkthdr *pkthdr);
void IEEE80211_CTL_Frame(const u_char *data, ieee80211_frame *fdh);
void IEEE80211_DATA_Frame(const u_char *data, ieee80211_frame *fdh);

ieee80211_frame *IEEE80211_DS_ADDR(const u_char *data);
void IEEE80211_Information_Elements(const u_char *data, int datapoint, pcap_pkthdr *pkthdr);

QString MacADDR(u_int8_t* ADDR);
QString RSN_MacOUI(const u_char* OUI);

const char* RSN_Cipher_Suite(int type);
const char* RSN_Auth_Key(int type);

void MGT_Timestamp(const u_char *data, int datapoint);
void MGT_Beacon_Interval(const u_char *data, int datapoint);
void MGT_Capability_Info(const u_char *data, int datapoint);

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

        IEEE80211_Frame_Parser(data, pkthdr);
    }
}

void IEEE80211_Frame_Parser(const u_char *data, pcap_pkthdr *pkthdr) {
    /* Distribute System (DS) */
    ieee80211_frame *fdh = IEEE80211_DS_ADDR(data);

    /* Frame Control Field */
    switch(fdh->i_fc[0] & IEEE80211_FC0_TYPE_MASK)  /* Frame Type */
    {
        case IEEE80211_FC0_TYPE_MGT:    /* Management Frame */
            qDebug() << "Management";
            IEEE80211_MGT_Frame(data, fdh, pkthdr);
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

void IEEE80211_MGT_Frame(const u_char *data, ieee80211_frame *fdh, pcap_pkthdr *pkthdr) {
    /*
     *  Management frame subtype's fixed parameters contents
     *
     *               | AUTH_ALGO | AUTH_SEQ  | TIMESTAMP | BCON_ITVL | CPB_INFO  | LSTN_ITVL | CRNT_AP   | REASON | STATUS | AID |
     *  ASSOC_REQ    |           |           |           |           |     o     |     o     |           |        |        |     |
     *  ASSOC_RESP   |           |           |           |           |     o     |           |           |        |    o   |  o  |
     *  REASSOC_REQ  |           |           |           |           |     o     |     o     |     o     |        |        |     |
     *  REASSOC_RESP |           |           |           |           |     o     |           |           |        |    o   |  o  |
     *  PROBE_REQ    |           |           |           |           |           |           |           |        |        |     |
     *  PROBE_RESP   |           |           |     o     |     o     |     o     |           |           |        |        |     |
     *  BEACON       |           |           |     o     |     o     |     o     |           |           |        |        |     |
     *  DISASSOC     |           |           |           |           |           |           |           |    o   |        |     |
     *  AUTH         |     o     |     o     |           |           |           |           |           |        |    o   |     |
     *  DEAUTH       |           |           |           |           |           |           |           |    o   |        |     |
     *  ATIM         |           |           |           |           |           |           |           |        |        |     |
     */

    int datapoint = RADIOTAPLEN + sizeof(*fdh); /* radiotap length + frame lenth */

    /*  Management Frame Subtype */
    switch(fdh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
    {
        case IEEE80211_FC0_SUBTYPE_ASSOC_REQ:
            datapoint += 4;
            break;

        case IEEE80211_FC0_SUBTYPE_ASSOC_RESP:
            /* CPB Information */   datapoint += 2;
            /* Status code */       datapoint += 2;
            /* Association ID */    datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_REASSOC_REQ:
            datapoint += 6;
            break;

        case IEEE80211_FC0_SUBTYPE_REASSOC_RESP:
            /* CPB Information */   datapoint += 2;
            /* Status code */       datapoint += 2;
            /* Association ID */    datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_PROBE_REQ:
            /* NULL */
            break;

        case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
            MGT_Timestamp(data, datapoint);
            MGT_Beacon_Interval(data, datapoint);   datapoint += 10;
            MGT_Capability_Info(data, datapoint);   datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_BEACON:
            MGT_Timestamp(data, datapoint);
            MGT_Beacon_Interval(data, datapoint);   datapoint += 10;
            MGT_Capability_Info(data, datapoint);   datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_ATIM:
            return;
            break;

        case IEEE80211_FC0_SUBTYPE_DISASSOC:
            /* Reason code */   datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_AUTH:
            /* Auth Algo */     datapoint += 2;
            /* Auth SEQ */      datapoint += 2;
            /* Status code */   datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_DEAUTH:
            /* Reason code */   datapoint += 2;
            break;

        case IEEE80211_FC0_SUBTYPE_ACTION:
            break;

        case IEEE80211_FC0_SUBTYPE_ACTION_NOACK:
            break;
    }

    /* tagged parameters */
    IEEE80211_Information_Elements(data, datapoint, pkthdr);

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

void IEEE80211_Information_Elements(const u_char *data, int datapoint, pcap_pkthdr *pkthdr) {
    /* Check Elements ID */
    while(datapoint < (int)pkthdr->caplen - 4)      /* Packet Length - Frame check sequence(4) */
    {

        int ELEMID = *(data + datapoint);
        ++datapoint;
        int ELELen = *(data + datapoint);
        ++datapoint;

        switch(ELEMID)
        {
            case IEEE80211_ELEMID_SSID:
                {
                    QString SSID;
                    unsigned int SSIDLen = ELELen;
                    for (unsigned int i = 0; i < SSIDLen; ++i)
                    {
                        SSID.append(*(data + datapoint + i));
                    }
                    qDebug() << SSID;
                    break;
                }

            case IEEE80211_ELEMID_RATES:        /* Supported Rate 500Kbps */
            /*
             * 802.11b is started by 0x80   ex) 0x82 = 1Mbps
             */
                {
                    double Rates[ELELen];
                    for (int i = 0; i < ELELen; ++i)
                    {
                        if (*(data + datapoint + i) & 0x80)     /* 802.11b */
                            Rates[i] = (double)(*(data + datapoint + i) - 0x80)/2;
                        else
                            Rates[i] = (*(data + datapoint + i)) >> 1;
                    }
                }
                break;

            case IEEE80211_ELEMID_FHPARMS:
                break;

            case IEEE80211_ELEMID_DSPARMS:      /* DS Prameter Set (Channel) */
                qDebug() << "Channel:" << *(data + datapoint);
                break;

            case IEEE80211_ELEMID_CFPARMS:
                break;

            case IEEE80211_ELEMID_TIM:          /* Traffic Indication Map */
                break;

            case IEEE80211_ELEMID_IBSSPARMS:
                break;

            case IEEE80211_ELEMID_COUNTRY:
                break;

            case IEEE80211_ELEMID_CHALLENGE:
                break;

            case IEEE80211_ELEMID_PWRCNSTR:
                break;

            case IEEE80211_ELEMID_PWRCAP:
                break;

            case IEEE80211_ELEMID_TPCREQ:
                break;

            case IEEE80211_ELEMID_TPCREP:
                break;

            case IEEE80211_ELEMID_SUPPCHAN:
                break;

            case IEEE80211_ELEMID_CSA:
                break;

            case IEEE80211_ELEMID_MEASREQ:
                break;

            case IEEE80211_ELEMID_MEASREP:
                break;

            case IEEE80211_ELEMID_QUIET:
                break;

            case IEEE80211_ELEMID_IBSSDFS:
                break;

            case IEEE80211_ELEMID_ERP:
                break;

            case IEEE80211_ELEMID_HTCAP:
                break;

            case IEEE80211_ELEMID_QOS:
                break;

            case IEEE80211_ELEMID_RSN:          /* Robust Secure Network (Encryption & Authentication) */
                {
                    int offset = 0;
                    qDebug() << "RSN Version:" << *((u_int16_t*)(data + datapoint));                    offset += 2;
                    qDebug() << "Group_Cipher_OUI" << RSN_MacOUI(&*(data + datapoint + offset));        offset += 3;
                    qDebug() << "Group_Cipher" << RSN_Cipher_Suite((int)*(data + datapoint + offset));  offset += 1;
                    int PairwireCount = *((u_int16_t*)(data + datapoint + offset));                     offset += 2;
                    for (int i = 0; i < PairwireCount; ++i)
                    {
                        qDebug() << "Pairwire OUI" << RSN_MacOUI(&*(data + datapoint + offset));        offset += 3;
                        qDebug() << "Pairwire:" << RSN_Cipher_Suite(*(data + datapoint + offset));      offset += 1;
                    }
                    int AuthCount = *((u_int16_t*)(data + datapoint + offset));                         offset += 2;
                    for (int i = 0; i < AuthCount; ++i)
                    {
                        qDebug() << "Auth OUI" << RSN_MacOUI(&*(data + datapoint + offset));            offset += 3;
                        qDebug() << "Auth:" << RSN_Auth_Key(*(data + datapoint + offset));              offset += 1;
                    }
                }
                break;

            case IEEE80211_ELEMID_XRATES:       /* Extended Supported Rates 500Kbps */
                {
                    double Rates[ELELen];
                    for (int i = 0; i < ELELen; ++i)
                    {
                        if (*(data + datapoint + i) & 0x80)     /* 802.11b */
                            Rates[i] = (double)(*(data + datapoint + i) - 0x80)/2;
                        else
                            Rates[i] = (*(data + datapoint + i)) >> 1;
                    }
                }
                break;

            case IEEE80211_ELEMID_HTINFO:
                break;

            case IEEE80211_ELEMID_TPC:
                break;

            case IEEE80211_ELEMID_CCKM:
                break;

            case IEEE80211_ELEMID_VENDOR:
                break;

        }

        datapoint += ELELen;

    }

}

QString MacADDR(u_int8_t* ADDR) {
    QString MacADDR;

    MacADDR.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", ADDR[0], ADDR[1], ADDR[2], ADDR[3], ADDR[4], ADDR[5]);

    return MacADDR;
}

QString RSN_MacOUI(const u_char* OUI) {
    QString MacOUI;

    MacOUI.sprintf("%02X-%02X-%02X", OUI[0], OUI[1], OUI[2]);

    return MacOUI;
}

const char* RSN_Cipher_Suite(int type) {
    const char* typeList[] = {"",
        "WEP",      /* 1 */
        "TKIP",     /* 2 */
        "WRAP",     /* 3 */
        "CCMP",     /* 4 */
        "WEP-104",  /* 5 */
    };

    if (type <= 5)
        return typeList[type];
    else
        return 0;
}

const char* RSN_Auth_Key(int type) {
    const char* typeList[] = {"",
        "802.1X",           /* 1 */
        "PSK",              /* 2 */
        "FT over 802.1X",   /* 3 */
    };

    if (type <= 3)
        return typeList[type];
    else
        return 0;
}

inline void MGT_Timestamp(const u_char *data, int datapoint) {
    qDebug() << "Timestamp:" << hex << *((u_int64_t*)(data + datapoint));

}

inline void MGT_Beacon_Interval(const u_char *data, int datapoint) {
    qDebug() << "Beacon Interval:" << IEEE80211_BEACON_INTERVAL(data + datapoint) * 1.024 << "ms";
}

void MGT_Capability_Info(const u_char *data, int datapoint) {
    /* Capabilities Information */
    switch (IEEE80211_CAPABILITY(data + datapoint) & 0xFFFF)
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
}

//#undef IEEE80211_CAPABILITY(beacon)

//void MGT_Reason_Code() {u

//}

//void MGT_Status_Code() {

//}
