/*
 * Copyright (C) 2024 KeePassXC Team <team@keepassxc.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or (at your option)
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "FidoAuthenticationFactor.h"

#if defined(Q_OS_WIN) && defined(Q_CC_MSVC)
#include "keys/drivers/WindowsFido2.h"
#include <QDebug>
#endif

FidoAuthenticationFactor::FidoAuthenticationFactor(QSharedPointer<AuthenticationFactor> factor)
{
    m_name = factor->getName();
    if (factor->getKeyType() != KeyType::NONE) {
        setKeyType(factor->getKeyType());
    }
    m_keySalt = factor->getKeySalt();
    m_wrappedKey = factor->getWrappedKey();
    m_factorType = FACTOR_TYPE_FIDO_ES256;
}

void FidoAuthenticationFactor::setCredentialID(const QByteArray& credentialID)
{
    m_credentialID = credentialID;
}

QByteArray FidoAuthenticationFactor::getCredentialID() const
{
    return m_credentialID;
}

QString FidoAuthenticationFactor::relyingPartyId()
{
    // Experimental identifier for fixtures. Production enrollment needs an upstream-assigned RP ID.
    return QStringLiteral("keepassxc-fido2-probe.example.com");
}

QByteArray FidoAuthenticationFactor::getUnwrappingKey(QSharedPointer<AuthenticationFactorUserData> userData,
                                                     const QByteArray& challenge) const
{
    Q_UNUSED(userData)
#if defined(Q_OS_WIN) && defined(Q_CC_MSVC)
    // Check the complete factor record before asking the user to touch a key.
    if (m_credentialID.isEmpty() || challenge.size() != 32 || m_keySalt.size() != 16 || m_wrappedKey.size() != 32) {
        return {};
    }
    QString error;
    auto secret = WindowsFido2::deriveSecret(relyingPartyId(), m_credentialID, challenge, error);
    if (secret.isEmpty()) {
        qWarning().noquote() << error;
    }
    return secret;
#else
    Q_UNUSED(challenge)
    return {};
#endif
}
