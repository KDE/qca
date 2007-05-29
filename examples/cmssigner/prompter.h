/*
 * Copyright (C) 2007  Justin Karneges <justin@affinix.com>
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
	Private *d;
};

#endif
