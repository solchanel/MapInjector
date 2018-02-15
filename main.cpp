#include "main.h"

int main(int argc, char **argv)
{
	INIReader Settings("settings.ini");
	if (Settings.ParseError() < 0) {
		cerr << "Cannot open settings.ini file" << endl;
		cin.get();
		return EXIT_FAILURE;
	}

	std::string processname = Settings.Get("Settings", "ProcessName", "");
	std::string dllname = Settings.Get("Settings", "DllFile", "");
	int timeout = Settings.GetInteger("Settings", "Timeout", 10);

	bool IsCrossMap = Settings.GetBoolean("Settings", "CrossInjection", false);

	if (dllname.length() < 1) {
		cerr << "No DllFile found in settings.ini file" << endl;
		cin.get();
		return EXIT_FAILURE;
	}
	if (processname.length() < 1) {
		cerr << "No ProcessName found in settings.ini file" << endl;
		cin.get();
		return EXIT_FAILURE;
	}

	unsigned long processid = -1;
	while (timeout || processid == -1) {
		processid = GetProcessIdByName((char *)processname.c_str());
		Sleep(20);
		timeout--;
	}

	cout << "Found process! " << processid << endl;

	if (processid == -1) {
		cerr << "Process not found, timeout" << endl;
		return EXIT_SUCCESS;
	}

	MapRemoteModule(processid, (char *)dllname.c_str());
	cout << dllname << " have been mapped to " << processname << " exiting..." << endl;
	return EXIT_SUCCESS;
}