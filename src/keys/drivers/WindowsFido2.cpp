/*
 * Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or (at your option)
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "WindowsFido2.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>

#include <windows.h>
#include <webauthn.h>

#include <memory>

namespace
{
    constexpr auto SaltSize = WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH;
    constexpr auto MaxCredentialIdSize = 1024;
    constexpr auto TimeoutMilliseconds = 60000;

    class WebAuthn
    {
        HMODULE m_module;

    public:
        WebAuthn()
            : m_module(LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32))
        {
        }

        ~WebAuthn()
        {
            if (m_module) {
                FreeLibrary(m_module);
            }
        }

        WebAuthn(const WebAuthn&) = delete;
        WebAuthn& operator=(const WebAuthn&) = delete;

        decltype(&WebAuthNGetApiVersionNumber) version = resolve<decltype(version)>("WebAuthNGetApiVersionNumber");
        decltype(&WebAuthNAuthenticatorMakeCredential) makeCredential =
            resolve<decltype(makeCredential)>("WebAuthNAuthenticatorMakeCredential");
        decltype(&WebAuthNAuthenticatorGetAssertion) getAssertion =
            resolve<decltype(getAssertion)>("WebAuthNAuthenticatorGetAssertion");
        decltype(&WebAuthNFreeCredentialAttestation) freeAttestation =
            resolve<decltype(freeAttestation)>("WebAuthNFreeCredentialAttestation");
        decltype(&WebAuthNFreeAssertion) freeAssertion = resolve<decltype(freeAssertion)>("WebAuthNFreeAssertion");

        bool supportsHmacSecret() const
        {
            return version && makeCredential && getAssertion && freeAttestation && freeAssertion
                   && version() >= WEBAUTHN_API_VERSION_4;
        }

    private:
        template <typename Function> Function resolve(const char* name) const
        {
            return m_module ? reinterpret_cast<Function>(GetProcAddress(m_module, name)) : nullptr;
        }
    };

    HWND promptWindow()
    {
        auto window = GetActiveWindow();
        return window ? window : GetForegroundWindow();
    }

    QString windowsError(HRESULT result)
    {
        return QCoreApplication::translate("WindowsFido2", "Windows security key request failed (0x%1).")
            .arg(quint32(result), 8, 16, QLatin1Char('0'));
    }

    QByteArray clientData(const QString& rpId, const QString& type)
    {
        quint32 challenge[8];
        QRandomGenerator::system()->fillRange(challenge);
        const QByteArray challengeBytes(reinterpret_cast<const char*>(challenge), sizeof(challenge));
        const auto encoded = challengeBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        return QJsonDocument(QJsonObject{{QStringLiteral("type"), type},
                                         {QStringLiteral("origin"), QStringLiteral("https://") + rpId},
                                         {QStringLiteral("challenge"), QString::fromLatin1(encoded)}})
            .toJson(QJsonDocument::Compact);
    }

    WEBAUTHN_CLIENT_DATA webAuthnClientData(QByteArray& json)
    {
        return {WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                DWORD(json.size()),
                reinterpret_cast<PBYTE>(json.data()),
                WEBAUTHN_HASH_ALGORITHM_SHA_256};
    }

    bool verifiedForRp(const QString& rpId, const BYTE* data, DWORD size)
    {
        constexpr size_t RpHashSize = 32;
        constexpr size_t MinimumAuthDataSize = RpHashSize + 1 + 4;
        constexpr BYTE UserPresentAndVerified = 0x01 | 0x04;
        return data && size >= MinimumAuthDataSize
               && (data[RpHashSize] & UserPresentAndVerified) == UserPresentAndVerified
               && QByteArray(reinterpret_cast<const char*>(data), RpHashSize)
                      == QCryptographicHash::hash(rpId.toUtf8(), QCryptographicHash::Sha256);
    }
} // namespace

QByteArray WindowsFido2::makeCredential(const QString& rpId, const QByteArray& userId, QString& error)
{
    error.clear();
    const WebAuthn api;
    if (!api.supportsHmacSecret()) {
        error = QCoreApplication::translate("WindowsFido2", "Windows WebAuthn with hmac-secret support is unavailable.");
        return {};
    }
    auto window = promptWindow();
    if (!window || rpId.isEmpty() || userId.isEmpty() || userId.size() > 64) {
        error = QCoreApplication::translate("WindowsFido2", "Missing security key enrollment parameters or window.");
        return {};
    }

    const auto wideRpId = rpId.toStdWString();
    WEBAUTHN_RP_ENTITY_INFORMATION rp{
        WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, wideRpId.c_str(), L"KeePassXC FIDO2", nullptr};
    auto userBytes = userId;
    WEBAUTHN_USER_ENTITY_INFORMATION user{WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
                                         DWORD(userBytes.size()),
                                         reinterpret_cast<PBYTE>(userBytes.data()),
                                         L"KeePassXC database",
                                         nullptr,
                                         L"KeePassXC database"};
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER parameter{WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                                                  WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                                                  WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256};
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS algorithms{1, &parameter};
    BOOL enableHmacSecret = TRUE;
    WEBAUTHN_EXTENSION extension{WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
                                 sizeof(enableHmacSecret),
                                 &enableHmacSecret};
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options{};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6;
    options.dwTimeoutMilliseconds = TimeoutMilliseconds;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    options.Extensions = {1, &extension};

    auto json = clientData(rpId, QStringLiteral("webauthn.create"));
    const auto client = webAuthnClientData(json);

    PWEBAUTHN_CREDENTIAL_ATTESTATION raw = nullptr;
    const auto result = api.makeCredential(window, &rp, &user, &algorithms, &client, &options, &raw);
    const std::unique_ptr<WEBAUTHN_CREDENTIAL_ATTESTATION, decltype(api.freeAttestation)> attestation(raw,
                                                                                                    api.freeAttestation);
    if (FAILED(result)) {
        error = windowsError(result);
        return {};
    }

    if (!attestation || !attestation->pbCredentialId || attestation->cbCredentialId == 0
        || attestation->cbCredentialId > MaxCredentialIdSize
        || !verifiedForRp(rpId, attestation->pbAuthenticatorData, attestation->cbAuthenticatorData)) {
        error = QCoreApplication::translate("WindowsFido2", "The security key did not return a verified credential.");
        return {};
    }

    // The first assertion confirms whether the authenticator actually enabled hmac-secret.
    return QByteArray(reinterpret_cast<const char*>(attestation->pbCredentialId), int(attestation->cbCredentialId));
}

QByteArray WindowsFido2::deriveSecret(const QString& rpId,
                                      const QByteArray& credentialId,
                                      const QByteArray& salt,
                                      QString& error)
{
    error.clear();
    const WebAuthn api;
    if (!api.supportsHmacSecret()) {
        error = QCoreApplication::translate("WindowsFido2", "Windows WebAuthn with hmac-secret support is unavailable.");
        return {};
    }
    auto window = promptWindow();
    if (!window || rpId.isEmpty() || credentialId.isEmpty() || credentialId.size() > MaxCredentialIdSize
        || salt.size() != SaltSize) {
        error = QCoreApplication::translate("WindowsFido2", "Missing or invalid security key request parameters.");
        return {};
    }

    auto allowedId = credentialId;
    WEBAUTHN_CREDENTIAL allowed{WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                                DWORD(allowedId.size()),
                                reinterpret_cast<PBYTE>(allowedId.data()),
                                WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY};
    auto saltBytes = salt;
    WEBAUTHN_HMAC_SECRET_SALT hmacSalt{SaltSize, reinterpret_cast<PBYTE>(saltBytes.data()), 0, nullptr};
    WEBAUTHN_HMAC_SECRET_SALT_VALUES salts{&hmacSalt, 0, nullptr};
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options{};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
    options.dwTimeoutMilliseconds = TimeoutMilliseconds;
    options.CredentialList = {1, &allowed};
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwFlags = WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG;
    options.pHmacSecretSaltValues = &salts;

    auto json = clientData(rpId, QStringLiteral("webauthn.get"));
    const auto client = webAuthnClientData(json);
    const auto wideRpId = rpId.toStdWString();

    PWEBAUTHN_ASSERTION raw = nullptr;
    const auto result = api.getAssertion(window, wideRpId.c_str(), &client, &options, &raw);
    const std::unique_ptr<WEBAUTHN_ASSERTION, decltype(api.freeAssertion)> assertion(raw, api.freeAssertion);
    if (FAILED(result)) {
        error = windowsError(result);
        return {};
    }

    if (!assertion || assertion->dwVersion < WEBAUTHN_ASSERTION_VERSION_3 || !assertion->pHmacSecret
        || assertion->pHmacSecret->cbFirst != SaltSize || !assertion->pHmacSecret->pbFirst
        || !assertion->Credential.pbId || assertion->Credential.cbId != DWORD(credentialId.size())
        || QByteArray(reinterpret_cast<const char*>(assertion->Credential.pbId), credentialId.size()) != credentialId
        || !verifiedForRp(rpId, assertion->pbAuthenticatorData, assertion->cbAuthenticatorData)) {
        error = QCoreApplication::translate("WindowsFido2", "The security key did not return a verified hmac-secret.");
        return {};
    }

    auto secret = assertion->pHmacSecret;
    const QByteArray output(reinterpret_cast<const char*>(secret->pbFirst), SaltSize);
    SecureZeroMemory(secret->pbFirst, SaltSize);
    return output;
}
