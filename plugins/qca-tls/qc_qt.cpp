/*
-----BEGIN QCMOD-----
name: Qt
-----END QCMOD-----
*/

//----------------------------------------------------------------------------
// qc_qt
//----------------------------------------------------------------------------
class qc_qt : public ConfObj
{
public:
	qc_qt(Conf *c) : ConfObj(c) {}
	QString name() const { return "Qt (Multithreaded) >= 3.0"; }
	QString shortname() const { return "qt"; }
	bool exec()
	{
		if(QT_VERSION >= 0x030000 && QT_THREAD_SUPPORT)
			return true;
		else
			return false;
	}
};
