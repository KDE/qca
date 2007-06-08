/*
 Copyright (C) 2007 Justin Karneges <justin@affinix.com>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef PROMPTER_H
#define PROMPTER_H

#include <QObject>

namespace QCA
{
	class SecureArray;
	class Event;
}

class Prompter : public QObject
{
	Q_OBJECT
public:
	Prompter(QObject *parent = 0);
	~Prompter();

protected:
	// called with every password event, to check for a known value.
	//   reimplement it to provide known/cached passwords.
	virtual QCA::SecureArray knownPassword(const QCA::Event &event);

	// called when a user-entered password is submitted.  note that this
	//   does not mean the password was correct.  to know if the password
	//   was correct, you'll have to match up the event information with
	//   the operation that triggered it.
	virtual void userSubmitted(const QCA::SecureArray &password, const QCA::Event &event);

private:
	class Private;
	friend class Private;
	Private *d;
};

#endif
