#include <QCoreApplication>
#include <QDebug>

#include <arpa/inet.h>
#include <pcap.h>
#include <ieee80211.h>

void IEEE80211_Frame_Parser(const u_char *data);

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

    /*frames struct*/
    struct ieee80211_frame *fdh = (struct ieee80211_frame *)(data + radiotapLen);

    /* Frame Control Field */
    switch(fdh->i_fc[0] & IEEE80211_FC0_TYPE_MASK)  /* Frame Type */
    {
        case IEEE80211_FC0_TYPE_MGT:    /* Management Frame */
            qDebug() << "Management";
            break;

        case IEEE80211_FC0_TYPE_CTL:    /* Control Frame */
            qDebug() << "Control";
            break;

        case IEEE80211_FC0_TYPE_DATA:   /* Data Frame */
            qDebug() << "Data";
            break;

        default:
            break;
    }

    switch(fdh->i_fc[1] & IEEE80211_FC1_DIR_MASK)    /* Distribute System (DS) */
    {
        case IEEE80211_FC1_DIR_NODS:    /* STA -> STA */
            break;

        case IEEE80211_FC1_DIR_TODS:    /* STA -> AP */
            break;

        case IEEE80211_FC1_DIR_FROMDS:  /* AP -> STA */
            break;

        case IEEE80211_FC1_DIR_DSTODS:  /* AP -> AP */
            break;
    }

}
