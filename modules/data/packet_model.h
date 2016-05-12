#ifndef PACKET_MODEL_H
#define PACKET_MODEL_H

#include <qvariant.h>
#include <qlist.h>
#include <QAbstractTableModel>

class PacketModel : public QAbstractTableModel {
    QList<QList<QVariant> > rows_data;
public:
    PacketModel(QObject * parent = 0) : QAbstractTableModel(parent) { }

    inline int rowCount(const QModelIndex & /*parent*/ = QModelIndex()) const { return rows_data.length(); }
    inline int columnCount(const QModelIndex & parent = QModelIndex()) const { return rows_data[parent.row()].length(); }
    QVariant data(const QModelIndex & index, int role) const;

    inline void setHeaders(const QStringList & hs) {
        int i = 0;
        for(QStringList::ConstIterator it = hs.cbegin(); it != hs.cend(); it++, i++)
            setHeaderData(i, Qt::Horizontal, *it);
    }
//    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
//    virtual bool setHeaderData(int section, Qt::Orientation orientation, const QVariant &value,
//                               int role = Qt::EditRole);
};

#endif // PACKET_MODEL_H
