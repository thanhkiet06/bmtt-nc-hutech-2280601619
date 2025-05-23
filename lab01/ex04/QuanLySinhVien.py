from SinhVien import SinhVien

class QuanLySinhVien:
    listSINHVIEN = []

    def generateID(self):
        maxID = 1
        if (self.soLuongSinhVien() > 0):
            maxID = self.listSINHVIEN[0]._id
            for sv in self.listSINHVIEN:
                if (maxID < sv._id):
                    maxID = sv._id
            maxID = maxID + 1
        return maxID

    def soLuongSinhVien(self):
        return self.listSINHVIEN.__len__()

    def nhapSinhVien(self):
        svID = self.generateID()
        name = input("Nhap ten sinh vien: ")
        sex = input("Nhap gioi tinh sinh vien: ")
        major = input("Nhap chuyen nganh cua sinh vien: ")
        diemTB = float(input("Nhap diem cua sinh vien: "))
        sv = SinhVien(svID, name, sex, major, diemTB)
        self.xepLoaiHocLuc(sv)
        self.listSINHVIEN.append(sv)

    def updateSinhVien(self, ID):
        sv: SinhVien = self.findByID(ID)
        if (sv != None):
            name = input("Nhap ten sinh vien: ")
            sex = input("Nhap gioi tinh sinh vien: ")
            major = input("Nhap chuyen nganh cua sinh vien: ")
            diemTB = float(input("Nhap diem cua sinh vien: "))
            sv._name = name
            sv._sex = sex
            sv._major = major
            sv._diemTB = diemTB
            self.xepLoaiHocLuc(sv)

    def sortByID(self):
        self.listSINHVIEN.sort(key=lambda x: x._id, reverse=False)

    def sortByName(self):
        self.listSINHVIEN.sort(key=lambda x: x._name, reverse=False)

    def sortByDiemTB(self):
        self.listSINHVIEN.sort(key=lambda x: x._diemTB, reverse=False)

    def findByID(self, ID):
        searchResult = None
        if (self.soLuongSinhVien() > 0):
            for sv in self.listSINHVIEN:
                if (sv._id == ID):
                    searchResult = sv
        return searchResult

    def findByName(self, keyword):
        listSV = []
        if (self.soLuongSinhVien() > 0):
            for sv in self.listSINHVIEN:
                if (keyword.upper() in sv._name.upper()):
                    listSV.append(sv)
        return listSV

    def deleteById(self, ID):
        isDeleted = False
        sv = self.findByID(ID)
        if (sv != None):
            self.listSINHVIEN.remove(sv)
            isDeleted = True
        return isDeleted

    def xepLoaiHocLuc(self, sv: SinhVien):
        if (sv._diemTB >= 8):
            sv._hocLuc = "Giỏi"
        elif (sv._diemTB >= 6.5):
            sv._hocLuc = "Trung bình"
        elif (sv._diemTB >= 5):
            sv._hocLuc = "Yếu"
        else:
            sv._hocLuc = "Kém"

    def showSinhVien(self, listSV):
        print("{:<8} {:<18} {:<8} {:<8} {:<8} {:<8}".format("ID", "NAME", "SEX", "MAJOR", "Diem TB", "HOC LUC"))
        if (listSV.__len__() > 0):
            for sv in listSV:
                print("{:<8} {:<18} {:<8} {:<8} {:<8} {:<8}".format(sv._id, sv._name, sv._sex, sv._major, sv._diemTB, sv._hocLuc))
        print("\n")

    def getListSinhVien(self):
        return self.listSINHVIEN