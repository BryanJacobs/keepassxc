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

#include <QApplication>
#include <QLabel>
#include <QTemporaryDir>
#include <QTest>

#include <botan/mem_ops.h>

#include <memory>

#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "crypto/Crypto.h"
#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"
#include "format/Kdbx4Reader.h"
#include "format/KeePass2Reader.h"
#include "format/KeePass2Writer.h"
#include "format/multifactor/FidoAuthenticationFactor.h"
#include "keys/MultiAuthenticationHeaderKey.h"
#include "keys/PasswordKey.h"
#include "keys/drivers/WindowsFido2.h"

class TestWindowsFido2 : public QObject
{
    Q_OBJECT

private slots:
    void testDisposableDatabase();
};

namespace
{
    bool hardwareTestRequested()
    {
        return qEnvironmentVariableIntValue("KPXC_TEST_FIDO2_HARDWARE") == 1;
    }
}

void TestWindowsFido2::testDisposableDatabase()
{
    if (!hardwareTestRequested()) {
        QSKIP("Set KPXC_TEST_FIDO2_HARDWARE=1 on an interactive Windows desktop to test a physical key.");
    }

    QVERIFY(Crypto::init());
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const auto path = dir.filePath(QStringLiteral("Fido2HardwareTest.kdbx"));
    const auto savedPath = dir.filePath(QStringLiteral("Fido2HardwareTest-saved.kdbx"));
    const auto challenge = randomGen()->randomArray(32);
    const auto iv = randomGen()->randomArray(16);
    const auto rpId = FidoAuthenticationFactor::relyingPartyId();

    QLabel window;
    window.setWindowTitle(QStringLiteral("KeePassXC FIDO2 hardware test"));
    window.setAlignment(Qt::AlignCenter);
    window.setMinimumSize(435, 100);
    window.setWordWrap(true);
    const auto prompt = [&](const QString& text) {
        window.setText(text);
        QCoreApplication::processEvents();
        qInfo().noquote() << text;
    };
    window.show();
    window.raise();
    window.activateWindow();
    QVERIFY2(QTest::qWaitForWindowExposed(&window), "The test window is unavailable on this desktop.");

    prompt(QStringLiteral("Approve the KeePassXC FIDO2 test credential on your security key."));
    QString error;
    const auto credentialId = WindowsFido2::makeCredential(rpId, randomGen()->randomArray(32), error);
    QVERIFY2(!credentialId.isEmpty(), qPrintable(error));

    prompt(QStringLiteral("Approve the security key request to create the disposable database."));
    auto secret = WindowsFido2::deriveSecret(rpId, credentialId, challenge, error);
    QVERIFY2(secret.size() == 32, qPrintable(error));

    auto hardwareKey = randomGen()->randomArray(32);
    auto wrappedKey = hardwareKey;
    SymmetricCipher cipher;
    const auto initialized = cipher.init(SymmetricCipher::Aes256_CBC_UNPADDED, SymmetricCipher::Encrypt, secret, iv);
    Botan::secure_scrub_memory(secret.data(), secret.size());
    QVERIFY2(initialized, qPrintable(cipher.errorString()));
    QVERIFY2(cipher.finish(wrappedKey), qPrintable(cipher.errorString()));

    const auto factorXml = QStringLiteral(
                               "<FactorInfo><CompatVersion>1</CompatVersion><Group><Challenge>%1</Challenge>"
                               "<Factor><Name>Hardware test</Name><TypeUUID>%2</TypeUUID><KeyType>AES-CBC</KeyType>"
                               "<KeySalt>%3</KeySalt><WrappedKey>%4</WrappedKey><CredentialID>%5</CredentialID>"
                               "</Factor></Group></FactorInfo>")
                               .arg(QString::fromLatin1(challenge.toBase64()),
                                    QStringLiteral(FACTOR_TYPE_FIDO_ES256),
                                    QString::fromLatin1(iv.toBase64()),
                                    QString::fromLatin1(wrappedKey.toBase64()),
                                    QString::fromLatin1(credentialId.toBase64()));

    auto password = QSharedPointer<PasswordKey>::create();
    password->setPassword(QStringLiteral("disposable hardware test password"));
    auto passwordOnly = QSharedPointer<CompositeKey>::create();
    passwordOnly->addKey(password);
    auto combined = QSharedPointer<CompositeKey>::create();
    combined->addKey(password);
    auto extraKey = QSharedPointer<MultiAuthenticationHeaderKey>::create(
        QSharedPointer<const AuthenticationFactorInfo>{}, passwordOnly);
    extraKey->setRawKey(hardwareKey);
    Botan::secure_scrub_memory(hardwareKey.data(), hardwareKey.size());
    combined->addKey(extraKey);

    Database source;
    source.setFormatVersion(KeePass2::FILE_VERSION_4);
    source.publicCustomData().insert(QStringLiteral(AUTHENTICATION_FACTORS_HEADER_KEY), factorXml);
    auto entry = new Entry;
    entry->setUuid(QUuid::createUuid());
    entry->setTitle(QStringLiteral("Disposable test entry"));
    entry->setGroup(source.rootGroup());
    QVERIFY2(source.setKey(combined, true, true), qPrintable(source.keyError()));
    KeePass2Writer writer;
    QVERIFY2(writer.writeDatabase(path, &source), qPrintable(writer.errorString()));

    Database headerOnly;
    KeePass2Reader headerReader;
    QVERIFY2(headerReader.readDatabase(path, {}, &headerOnly), qPrintable(headerReader.errorString()));
    QCOMPARE(headerOnly.publicCustomData().value(QStringLiteral(AUTHENTICATION_FACTORS_HEADER_KEY)).toString(), factorXml);
    prompt(QStringLiteral("Approve the security key request to reopen the disposable database."));
    Database opened;
    KeePass2Reader reader;
    QVERIFY2(reader.readDatabase(path, passwordOnly, &opened), qPrintable(reader.errorString()));
    QCOMPARE(opened.rootGroup()->entries().size(), 1);
    QCOMPARE(opened.rootGroup()->entries().first()->title(), QStringLiteral("Disposable test entry"));

    opened.rootGroup()->entries().first()->setTitle(QStringLiteral("Saved after FIDO2 unlock"));
    QVERIFY2(writer.writeDatabase(savedPath, &opened), qPrintable(writer.errorString()));

    prompt(QStringLiteral("Approve the last security key request to reopen the saved database."));
    Database reopened;
    KeePass2Reader savedReader;
    QVERIFY2(savedReader.readDatabase(savedPath, passwordOnly, &reopened), qPrintable(savedReader.errorString()));
    QCOMPARE(reopened.rootGroup()->entries().size(), 1);
    QCOMPARE(reopened.rootGroup()->entries().first()->title(), QStringLiteral("Saved after FIDO2 unlock"));
}

int main(int argc, char* argv[])
{
    std::unique_ptr<QCoreApplication> app;
    if (hardwareTestRequested()) {
        app = std::make_unique<QApplication>(argc, argv);
    } else {
        app = std::make_unique<QCoreApplication>(argc, argv);
    }
    TestWindowsFido2 test;
    return QTest::qExec(&test, argc, argv);
}

#include "TestWindowsFido2.moc"
