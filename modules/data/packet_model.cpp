#include "packet_model.h"

QVariant PacketModel::data(const QModelIndex & index, int role) const {
    if (role == Qt::DisplayRole) {
        return rows_data[index.row()][index.column()];
    }
    return QVariant();
}

//QVariant Model::headerData(int section, Qt::Orientation orientation, int role) const {

//if(orientation == Qt::Horizontal) {

//    if(role == Qt::DisplayRole) {

//        return header.at(section);

//    }// if

//}// if

//return QAbstractTableModel::headerData(section, orientation, role);

//}
