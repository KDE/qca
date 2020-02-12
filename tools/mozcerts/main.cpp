/*
 * Copyright (C) 2005  Justin Karneges <justin@affinix.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

/* mozilla certdata converter.  adapted from the debian ruby script */

#include <QtCrypto>

#include <QCoreApplication>
#include <QFile>
#include <QTextStream>

QStringList splitWithQuotes(const QString &in, char c);

int main(int argc, char **argv)
{
	QCA::Initializer qcaInit;
	QCoreApplication app(argc, argv);

	if(argc < 3)
	{
		printf("usage: mozcerts [certdata.txt] [outfile.pem]\n");
		return 0;
	}

	QFile infile(QString::fromLocal8Bit(argv[1]));
	if(!infile.open(QFile::ReadOnly))
	{
		fprintf(stderr, "Error opening input file\n");
		return 1;
	}

	QFile outfile(QString::fromLocal8Bit(argv[2]));
	if(!outfile.open(QFile::WriteOnly | QFile::Truncate))
	{
		fprintf(stderr, "Error opening output file\n");
		return 1;
	}

	int count = 0;
	QString name;
	QTextStream ts(&infile);
	while(!ts.atEnd())
	{
		QString line = ts.readLine();
		if(QRegExp(QLatin1String("^#")).indexIn(line) != -1)
			continue;
		if(QRegExp(QLatin1String("^\\s*$")).indexIn(line) != -1)
			continue;
		line = line.trimmed();

		if(QRegExp(QLatin1String("CKA_LABEL")).indexIn(line) != -1)
		{
			QStringList list = splitWithQuotes(line, ' ');
			if(list.count() != 3)
				continue;

			name = list[2];
			// make an output filename based on the name
			//outname = name.replace(QRegExp("\\/"), "_")
			//	.replace(QRegExp("\\s+"), "_")
			//	.replace(QRegExp("[()]"), "=")
			//	.replace(QRegExp(","), "_") + ".pem";
			continue;
		}
		else if(QRegExp(QLatin1String("CKA_VALUE MULTILINE_OCTAL")).indexIn(line) != -1)
		{
			QByteArray buf;
			while(!ts.atEnd())
			{
				line = ts.readLine();
				if(QRegExp(QLatin1String("^END")).indexIn(line) != -1)
					break;
				line = line.trimmed();
				QRegExp rx(QLatin1String("\\\\([0-3][0-7][0-7])"));
				int pos = 0;
				while((pos = rx.indexIn(line, pos)) != -1)
				{
					QString str = rx.capturedTexts().at(1);
					uchar c = str.toInt(nullptr, 8);
					buf.append(c);
					pos += rx.matchedLength();
				}
			}

			printf(">> [%s], %d bytes\n", qPrintable(name), buf.size());

			QTextStream ts(&outfile);
			ts << "-----BEGIN CERTIFICATE-----" << '\n';
			QCA::Base64 enc;
			enc.setLineBreaksEnabled(true);
			enc.setLineBreaksColumn(64);
			ts << enc.arrayToString(buf) << '\n';
			ts << "-----END CERTIFICATE-----" << '\n';

			++count;
		}
	}
	printf("Wrote %d certs to [%s]\n", count, argv[2]);

	return 0;
}

int find_notchar(const QString &str, char c, int offset)
{
	for(int n = offset; n < str.length(); ++n)
	{
		if(str[n] != QLatin1Char(c))
			return n;
	}
	return -1;
}

QStringList splitWithQuotes(const QString &in, char c)
{
	QStringList result;
	int at = 0;
	if(in[at] == QLatin1Char(c))
		at = find_notchar(in, c, at);
	while(at != -1)
	{
		bool quote = false;
		int end;
		QString str;
		if(in[at] == QLatin1Char('\"'))
		{
			quote = true;
			++at;
			end = in.indexOf(QLatin1Char('\"'), at);
			if(end == -1)
				break;
		}
		else
			end = in.indexOf(QLatin1Char(c), at);

		if(end != -1)
			str = in.mid(at, end - at);
		else
			str = in.mid(at);

		if(!str.isEmpty())
			result += str;

		if(quote)
			end = in.indexOf(QLatin1Char(c), end);

		if(end != -1)
			at = find_notchar(in, c, end);
		else
			at = -1;
	}
	return result;
}

