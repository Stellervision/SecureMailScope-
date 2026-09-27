import { useEffect, useRef, useState } from "react";
import "./App.css";

import {
  assessRecipient,
  decryptMessage,
  encryptMessage,
  extractEnvelope,
  formatEnvelopeForEmail,
  getRecipientPublicKey,
  registerIdentity,
} from "./services/crypto";
import { API_BASE } from "./services/config";
import SecurityReview from "./components/compose/SecurityReview";
import E2EIdentityPanel from "./components/security/E2EIdentityPanel";
const MAX_TOTAL_ATTACHMENT_SIZE = 10 * 1024 * 1024;

const EMPTY_MAIL_ACCOUNT = {
  connected: false,
  account_id: null,
  sender_email: "",
  smtp: null,
  provider: null,
};

function App() {
  const [activeView, setActiveView] = useState("compose");

  const [recipient, setRecipient] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");

  const [attachments, setAttachments] = useState([]);

  const [attachedMailAccounts, setAttachedMailAccounts] =
    useState([]);

  const [availableMailAccounts, setAvailableMailAccounts] =
    useState([]);

  const [savedMailAccounts, setSavedMailAccounts] =
    useState([]);

  const [selectedAccountId, setSelectedAccountId] =
    useState("");

  const [attachPanelOpen, setAttachPanelOpen] =
    useState(false);

  const [addMailboxPanelOpen, setAddMailboxPanelOpen] =
    useState(false);

  const [attachSelectionId, setAttachSelectionId] =
    useState("");

  const [newMailboxEmail, setNewMailboxEmail] =
    useState("");

  const [newMailboxUsername, setNewMailboxUsername] =
    useState("");

  const [newMailboxPassword, setNewMailboxPassword] =
    useState("");

  const [newMailboxHost, setNewMailboxHost] =
    useState("");

  const [newMailboxPort, setNewMailboxPort] =
    useState("587");

  const [newMailboxSecurityMode, setNewMailboxSecurityMode] =
    useState("starttls");

  const [newMailboxProvider, setNewMailboxProvider] =
    useState("");

  const [mailboxSaving, setMailboxSaving] =
    useState(false);

  const [mailboxRemovingId, setMailboxRemovingId] =
    useState("");

  const [mailAccount, setMailAccount] = useState(
    EMPTY_MAIL_ACCOUNT
  );

  const [mailAccountLoading, setMailAccountLoading] =
    useState(true);

  const [accountConnecting, setAccountConnecting] =
    useState(false);

  const [accountError, setAccountError] = useState(null);

  const [oauthLoading, setOauthLoading] =
    useState("");

  const [assessment, setAssessment] = useState(null);
  const [loading, setLoading] = useState(false);

  const [sendLoading, setSendLoading] = useState(false);
  const [sendResult, setSendResult] = useState(null);

  const [inboxMessages, setInboxMessages] = useState([]);
  const [inboxLoading, setInboxLoading] = useState(false);
  const [inboxError, setInboxError] = useState(null);

  const [selectedMessage, setSelectedMessage] =
    useState(null);

  // Result of publishing this browser's E2E key for the connected
  // mailbox. "conflict" means senders encrypt to a key this browser
  // cannot decrypt, so it is surfaced in the inbox.
  const [identityRegistration, setIdentityRegistration] =
    useState(null);

  const [messageLoading, setMessageLoading] =
    useState(false);


  const loadMailboxState = async () => {
    setMailAccountLoading(true);
    setAccountError(null);

    try {
      const [
        accountsResponse,
        availableResponse,
        configuredResponse,
        connectionResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/api/mailbox/accounts`),
        fetch(`${API_BASE}/api/mailbox/available-accounts`),
        fetch(`${API_BASE}/api/mailbox/configured-accounts`),
        fetch(`${API_BASE}/api/send/account`),
      ]);

      const accountsData =
        await accountsResponse.json();

      const availableData =
        await availableResponse.json();

      const configuredData =
        await configuredResponse.json();

      const connectionData =
        await connectionResponse.json();

      if (!accountsResponse.ok) {
        throw new Error(
          accountsData.detail ||
            "Unable to load attached mailboxes."
        );
      }

      if (!availableResponse.ok) {
        throw new Error(
          availableData.detail ||
            "Unable to load available mailboxes."
        );
      }

      if (!configuredResponse.ok) {
        throw new Error(
          configuredData.detail ||
            "Unable to load saved mailboxes."
        );
      }

      if (!connectionResponse.ok) {
        throw new Error(
          connectionData.detail ||
            "Unable to load mailbox connection."
        );
      }

      const attachedAccounts =
        accountsData.accounts || [];

      const availableAccounts =
        availableData.accounts || [];

      const configuredAccounts =
        configuredData.accounts || [];

      const connectedAccount =
        connectionData.account ||
        EMPTY_MAIL_ACCOUNT;

      setAttachedMailAccounts(
        attachedAccounts
      );

      setAvailableMailAccounts(
        availableAccounts
      );

      setSavedMailAccounts(
        configuredAccounts
      );

      setMailAccount(
        connectedAccount || EMPTY_MAIL_ACCOUNT
      );

      if (
        connectedAccount?.connected &&
        connectedAccount.account_id
      ) {
        setSelectedAccountId(
          connectedAccount.account_id
        );
      } else {
        setSelectedAccountId("");
      }
    } catch (error) {
      console.error(
        "Unable to load mailbox state:",
        error
      );

      setAttachedMailAccounts([]);
      setAvailableMailAccounts([]);
      setSavedMailAccounts([]);
      setSelectedAccountId("");
      setMailAccount(EMPTY_MAIL_ACCOUNT);

      setAccountError(
        error.message ||
          "Unable to load mailbox state."
      );
    } finally {
      setMailAccountLoading(false);
    }
  };

  const refreshMailboxState = async () => {
    try {
      const [
        accountsResponse,
        availableResponse,
        configuredResponse,
        connectionResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/api/mailbox/accounts`),
        fetch(`${API_BASE}/api/mailbox/available-accounts`),
        fetch(`${API_BASE}/api/mailbox/configured-accounts`),
        fetch(`${API_BASE}/api/send/account`),
      ]);

      const accountsData =
        await accountsResponse.json();

      const availableData =
        await availableResponse.json();

      const configuredData =
        await configuredResponse.json();

      const connectionData =
        await connectionResponse.json();

      if (!accountsResponse.ok) {
        throw new Error(
          accountsData.detail ||
            "Unable to refresh attached mailboxes."
        );
      }

      if (!availableResponse.ok) {
        throw new Error(
          availableData.detail ||
            "Unable to refresh available mailboxes."
        );
      }

      if (!configuredResponse.ok) {
        throw new Error(
          configuredData.detail ||
            "Unable to refresh saved mailboxes."
        );
      }

      if (!connectionResponse.ok) {
        throw new Error(
          connectionData.detail ||
            "Unable to refresh mailbox connection."
        );
      }

      const accounts =
        accountsData.accounts || [];

      const availableAccounts =
        availableData.accounts || [];

      const configuredAccounts =
        configuredData.accounts || [];

      const connectedAccount =
        connectionData.account ||
        EMPTY_MAIL_ACCOUNT;

      setAttachedMailAccounts(accounts);

      setAvailableMailAccounts(
        availableAccounts
      );

      setSavedMailAccounts(
        configuredAccounts
      );

      setMailAccount(
        connectedAccount || EMPTY_MAIL_ACCOUNT
      );

      if (
        connectedAccount?.connected &&
        connectedAccount.account_id
      ) {
        setSelectedAccountId(
          connectedAccount.account_id
        );
      } else {
        // Functional update: this function is also called from the
        // OAuth listener registered on first render, where
        // selectedAccountId would be stale.
        setSelectedAccountId(
          (current) =>
            accounts.some(
              (account) =>
                account.account_id ===
                current
            )
              ? current
              : ""
        );
      }
    } catch (error) {
      console.error(
        "Unable to refresh mailbox state:",
        error
      );

      setAccountError(
        error.message ||
          "Unable to refresh mailbox state."
      );
    }
  };

  const openAttachMailbox = async () => {
    setAccountError(null);
    setAttachSelectionId("");
    setAddMailboxPanelOpen(false);

    try {
      const [
        availableResponse,
        configuredResponse,
      ] = await Promise.all([
        fetch(
          `${API_BASE}/api/mailbox/available-accounts`
        ),
        fetch(
          `${API_BASE}/api/mailbox/configured-accounts`
        ),
      ]);

      const availableData =
        await availableResponse.json();

      const configuredData =
        await configuredResponse.json();

      if (!availableResponse.ok) {
        throw new Error(
          availableData.detail ||
            "Unable to load available mailboxes."
        );
      }

      if (!configuredResponse.ok) {
        throw new Error(
          configuredData.detail ||
            "Unable to load saved mailboxes."
        );
      }

      setAvailableMailAccounts(
        availableData.accounts || []
      );

      setSavedMailAccounts(
        configuredData.accounts || []
      );

      setAttachPanelOpen(true);
    } catch (error) {
      setAccountError(
        error.message ||
          "Unable to load available mailboxes."
      );
    }
  };

  const closeAttachMailbox = () => {
    if (
      accountConnecting ||
      mailboxSaving ||
      mailboxRemovingId ||
      oauthLoading
    ) {
      return;
    }

    setAttachPanelOpen(false);
    setAttachSelectionId("");
    setAvailableMailAccounts([]);
  };

  const openAddMailbox = () => {
    if (
      accountConnecting ||
      mailboxSaving ||
      mailboxRemovingId ||
      oauthLoading
    ) {
      return;
    }

    setAccountError(null);
    setSendResult(null);

    setNewMailboxEmail("");
    setNewMailboxUsername("");
    setNewMailboxPassword("");
    setNewMailboxHost("");
    setNewMailboxPort("587");
    setNewMailboxSecurityMode("starttls");
    setNewMailboxProvider("");

    setAttachPanelOpen(false);
    setAttachSelectionId("");
    setAvailableMailAccounts([]);

    setAddMailboxPanelOpen(true);

    // The panel renders below the saved-mailbox list, often off
    // screen, so bring it into view once it exists.
    setTimeout(() => {
      document
        .getElementById(
          "add-mailbox-panel"
        )
        ?.scrollIntoView({
          block: "start",
        });
    }, 50);
  };

  const closeAddMailbox = () => {
    if (
      mailboxSaving ||
      oauthLoading
    ) {
      return;
    }

    setAddMailboxPanelOpen(false);
    setNewMailboxEmail("");
    setNewMailboxUsername("");
    setNewMailboxPassword("");
    setNewMailboxHost("");
    setNewMailboxPort("587");
    setNewMailboxSecurityMode("starttls");
    setNewMailboxProvider("");
  };

  const startOAuth = async (
    provider
  ) => {
    const normalizedProvider =
      normalizeOAuthProvider(
        provider
      );

    if (
      normalizedProvider !==
        "google" &&
      normalizedProvider !==
        "microsoft"
    ) {
      setAccountError(
        "Unsupported OAuth provider."
      );

      return;
    }

    if (
      accountConnecting ||
      mailboxSaving ||
      mailboxRemovingId ||
      oauthLoading
    ) {
      return;
    }

    setOauthLoading(
      normalizedProvider
    );

    setAccountError(null);
    setSendResult(null);

    try {
      const response =
        await fetch(
          `${API_BASE}/api/mailbox/oauth/${normalizedProvider}/start`
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            `Unable to start ${formatProviderName(
              normalizedProvider
            )} authorization.`
        );
      }

      const authorizationUrl =
        data.authorization_url;

      if (
        !authorizationUrl
      ) {
        throw new Error(
          data.message ||
            `${formatProviderName(
              normalizedProvider
            )} OAuth is not configured.`
        );
      }

      const popupWidth = 520;
      const popupHeight = 720;

      const left =
        window.screenX +
        Math.max(
          0,
          (window.outerWidth -
            popupWidth) /
            2
        );

      const top =
        window.screenY +
        Math.max(
          0,
          (window.outerHeight -
            popupHeight) /
            2
        );

      const popup =
        window.open(
          authorizationUrl,
          `securemailscope-${normalizedProvider}-oauth`,
          `width=${popupWidth},height=${popupHeight},left=${left},top=${top},resizable=yes,scrollbars=yes`
        );

      if (!popup) {
        throw new Error(
          "The authorization window was blocked by the browser. Allow pop-ups for SecureMailScope and try again."
        );
      }

      popup.focus();

      setAccountError(
        `${formatProviderName(
          normalizedProvider
        )} authorization opened in a new window. Complete authorization there.`
      );

      let checks = 0;

      const popupMonitor =
        window.setInterval(
          () => {
            checks += 1;

            if (
              popup.closed ||
              checks > 300
            ) {
              window.clearInterval(
                popupMonitor
              );

              setOauthLoading(
                ""
              );

              if (
                popup.closed
              ) {
                refreshMailboxState();
              }
            }
          },
          1000
        );
    } catch (error) {
      console.error(
        "Unable to start OAuth:",
        error
      );

      setOauthLoading("");

      setAccountError(
        error.message ||
          `Unable to start ${formatProviderName(
            normalizedProvider
          )} authorization.`
      );
    }
  };

  const createMailbox = async () => {
    const email =
      newMailboxEmail.trim();

    const username =
      newMailboxUsername.trim();

    const password =
      newMailboxPassword;

    const smtpHost =
      newMailboxHost.trim();

    const smtpPort =
      Number(
        String(newMailboxPort).trim()
      );

    const securityMode =
      newMailboxSecurityMode.trim();

    const provider =
      newMailboxProvider.trim();

    if (!email) {
      setAccountError(
        "Enter the mailbox email address."
      );

      return;
    }

    if (
      !email.includes("@") ||
      email.startsWith("@") ||
      email.endsWith("@")
    ) {
      setAccountError(
        "Enter a valid mailbox email address."
      );

      return;
    }

    if (!username) {
      setAccountError(
        "Enter the SMTP username."
      );

      return;
    }

    if (!password) {
      setAccountError(
        "Enter the credential required by the custom mail server."
      );

      return;
    }

    if (!smtpHost) {
      setAccountError(
        "Enter the SMTP host."
      );

      return;
    }

    if (
      !Number.isInteger(smtpPort) ||
      smtpPort < 1 ||
      smtpPort > 65535
    ) {
      setAccountError(
        "Enter a valid SMTP port between 1 and 65535."
      );

      return;
    }

    if (
      ![
        "starttls",
        "tls",
        "none",
      ].includes(securityMode)
    ) {
      setAccountError(
        "Select a valid SMTP security mode."
      );

      return;
    }

    setMailboxSaving(true);
    setAccountError(null);
    setSendResult(null);

    try {
      const response = await fetch(
        `${API_BASE}/api/mailbox/accounts`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            sender_email: email,
            username,
            password,
            smtp_host: smtpHost,
            smtp_port: smtpPort,
            security_mode: securityMode,
            provider: provider || "Custom SMTP",
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to save mailbox."
        );
      }

      setNewMailboxPassword("");

      setAddMailboxPanelOpen(false);

      setNewMailboxEmail("");
      setNewMailboxUsername("");
      setNewMailboxHost("");
      setNewMailboxPort("587");
      setNewMailboxSecurityMode(
        "starttls"
      );
      setNewMailboxProvider("");

      await refreshMailboxState();

      await openAttachMailbox();
    } catch (error) {
      setAccountError(
        error.message ||
          "Unable to save mailbox."
      );
    } finally {
      setMailboxSaving(false);
    }
  };

  const removeMailbox = async (
    accountId,
    senderEmail
  ) => {
    if (!accountId) {
      return;
    }

    if (
      accountConnecting ||
      mailboxSaving ||
      mailboxRemovingId ||
      oauthLoading
    ) {
      return;
    }

    const confirmed =
      window.confirm(
        `Remove the saved mailbox${senderEmail ? ` "${senderEmail}"` : ""} permanently?\n\nThis removes its stored configuration from SecureMailScope.`
      );

    if (!confirmed) {
      return;
    }

    setMailboxRemovingId(accountId);
    setAccountError(null);
    setSendResult(null);

    try {
      const response = await fetch(
        `${API_BASE}/api/mailbox/accounts/${encodeURIComponent(
          accountId
        )}`,
        {
          method: "DELETE",
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to remove mailbox."
        );
      }

      if (
        mailAccount?.account_id ===
        accountId
      ) {
        setMailAccount(
          EMPTY_MAIL_ACCOUNT
        );

        setSelectedAccountId("");
        setInboxMessages([]);
        setSelectedMessage(null);
      } else if (
        selectedAccountId ===
        accountId
      ) {
        setSelectedAccountId("");
      }

      await refreshMailboxState();
    } catch (error) {
      setAccountError(
        error.message ||
          "Unable to remove mailbox."
      );
    } finally {
      setMailboxRemovingId("");
    }
  };

  const attachMailbox = async () => {
    if (!attachSelectionId) {
      setAccountError(
        "Select a mailbox before attaching."
      );

      return;
    }

    setAccountConnecting(true);
    setAccountError(null);
    setSendResult(null);

    try {
      const response = await fetch(
        `${API_BASE}/api/mailbox/attach`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            account_id:
              attachSelectionId,
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to attach mailbox."
        );
      }

      const attachedAccount =
        data.account || null;

      await refreshMailboxState();

      if (
        attachedAccount?.account_id
      ) {
        setSelectedAccountId(
          attachedAccount.account_id
        );
      } else {
        setSelectedAccountId(
          attachSelectionId
        );
      }

      setAttachPanelOpen(false);
      setAttachSelectionId("");
      setAvailableMailAccounts([]);
    } catch (error) {
      setAccountError(
        error.message ||
          "Unable to attach mailbox."
      );
    } finally {
      setAccountConnecting(false);
    }
  };

  const selectMailbox = (
    accountId
  ) => {
    if (
      accountConnecting ||
      oauthLoading
    ) {
      return;
    }

    setSelectedAccountId(
      accountId
    );

    setAccountError(null);
    setSendResult(null);
  };

  const connectMailbox = async (
    accountId = selectedAccountId
  ) => {
    if (!accountId) {
      setAccountError(
        "Select an attached mailbox before connecting."
      );

      return;
    }

    const isAttached =
      attachedMailAccounts.some(
        (account) =>
          account.account_id ===
          accountId
      );

    if (!isAttached) {
      setAccountError(
        "Attach this mailbox before connecting it."
      );

      return;
    }

    setAccountConnecting(true);
    setAccountError(null);
    setSendResult(null);

    try {
      const response = await fetch(
        `${API_BASE}/api/mailbox/connect`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            account_id:
              accountId,
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to connect mailbox."
        );
      }

      const connectedAccount =
        data.account ||
        EMPTY_MAIL_ACCOUNT;

      setMailAccount(
        connectedAccount
      );

      setSelectedAccountId(
        connectedAccount.account_id ||
          accountId
      );

      await refreshMailboxState();
    } catch (error) {
      setAccountError(
        error.message ||
          "Unable to connect mailbox."
      );
    } finally {
      setAccountConnecting(false);
    }
  };

  const disconnectMailbox =
    async () => {
      setAccountConnecting(true);
      setAccountError(null);
      setSendResult(null);

      try {
        const response =
          await fetch(
            `${API_BASE}/api/mailbox/disconnect`,
            {
              method: "POST",
            }
          );

        const data =
          await response.json();

        if (!response.ok) {
          throw new Error(
            data.detail ||
              "Unable to disconnect mailbox."
          );
        }

        setMailAccount(
          EMPTY_MAIL_ACCOUNT
        );

        setSelectedAccountId("");
        setInboxMessages([]);
        setSelectedMessage(null);

        await refreshMailboxState();
      } catch (error) {
        setAccountError(
          error.message ||
            "Unable to disconnect mailbox."
        );
      } finally {
        setAccountConnecting(false);
      }
    };

  const detachMailbox = async (
    accountId
  ) => {
    if (!accountId) {
      return;
    }

    if (
      accountConnecting ||
      mailboxRemovingId
    ) {
      return;
    }

    setAccountConnecting(true);
    setAccountError(null);
    setSendResult(null);

    try {
      const response = await fetch(
        `${API_BASE}/api/mailbox/detach`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            account_id:
              accountId,
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to detach mailbox."
        );
      }

      if (
        mailAccount?.account_id ===
        accountId
      ) {
        setMailAccount(
          EMPTY_MAIL_ACCOUNT
        );

        setSelectedAccountId("");
        setInboxMessages([]);
        setSelectedMessage(null);
      } else if (
        selectedAccountId ===
        accountId
      ) {
        setSelectedAccountId("");
      }

      await refreshMailboxState();
    } catch (error) {
      setAccountError(
        error.message ||
          "Unable to detach mailbox."
      );
    } finally {
      setAccountConnecting(false);
    }
  };

  const checkRecipient = async () => {
    const normalizedRecipient =
      recipient.trim();

    if (!normalizedRecipient) {
      return;
    }

    setLoading(true);
    setAssessment(null);
    setSendResult(null);

    try {
      const [transportResponse, e2eAssessment] =
        await Promise.all([
          fetch(
            `${API_BASE}/api/send/check-recipient`,
            {
              method: "POST",
              headers: {
                "Content-Type":
                  "application/json",
              },
              body: JSON.stringify({
                recipient_email:
                  normalizedRecipient,
              }),
            }
          ).then(async (response) => {
            const data = await response.json();

            if (!response.ok) {
              throw new Error(
                data.detail ||
                  "Transport assessment failed."
              );
            }

            return data;
          }),
          assessRecipient(
            normalizedRecipient
          ),
        ]);

      setAssessment({
        ...transportResponse,
        e2e: e2eAssessment,
      });
    } catch (error) {
      setAssessment({
        error:
          error.message ||
          "Recipient assessment failed.",
        e2e: {
          status: "error",
          available: false,
          message:
            "Unable to determine recipient encryption support.",
        },
      });
    } finally {
      setLoading(false);
    }
  };

  const handleAttachmentChange = (
    event
  ) => {
    const selectedFiles =
      Array.from(
        event.target.files || []
      );

    if (
      selectedFiles.length ===
      0
    ) {
      return;
    }

    const existingSize =
      attachments.reduce(
        (total, file) =>
          total + file.size,
        0
      );

    const selectedSize =
      selectedFiles.reduce(
        (total, file) =>
          total + file.size,
        0
      );

    if (
      existingSize +
        selectedSize >
      MAX_TOTAL_ATTACHMENT_SIZE
    ) {
      setSendResult({
        type: "error",
        message:
          "The total attachment size cannot exceed 10 MB.",
      });

      event.target.value = "";
      return;
    }

    setAttachments(
      (current) => [
        ...current,
        ...selectedFiles,
      ]
    );

    setSendResult(null);
    event.target.value = "";
  };

  const removeAttachment = (
    indexToRemove
  ) => {
    setAttachments(
      (current) =>
        current.filter(
          (_, index) =>
            index !==
            indexToRemove
        )
    );

    setSendResult(null);
  };

  const getAttachmentTotalSize =
    () => {
      return attachments.reduce(
        (total, file) =>
          total + file.size,
        0
      );
    };

  const sendEmail = async () => {
    if (!mailAccount?.connected) {
      setSendResult({
        type: "error",
        message:
          "Select and connect a sending mailbox before sending.",
      });

      return;
    }

    const normalizedRecipient =
      recipient.trim();

    const normalizedSubject =
      subject.trim();

    const normalizedBody =
      body.trim();

    if (!normalizedRecipient) {
      setSendResult({
        type: "error",
        message:
          "Enter a recipient before sending.",
      });

      return;
    }

    const attachmentTotalSize =
      getAttachmentTotalSize();

    if (
      attachmentTotalSize >
      MAX_TOTAL_ATTACHMENT_SIZE
    ) {
      setSendResult({
        type: "error",
        message:
          "The total attachment size cannot exceed 10 MB.",
      });

      return;
    }

    setSendLoading(true);
    setSendResult(null);

    try {
      // Only reuse the key from the assessment if it belongs to the
      // recipient currently typed; otherwise the message could be
      // encrypted to a previously assessed recipient.
      let recipientKey =
        assessment?.e2e?.recipient ===
        normalizedRecipient.toLowerCase()
          ? assessment?.e2e?.key || null
          : null;

      if (!recipientKey) {
        recipientKey =
          await getRecipientPublicKey(
            normalizedRecipient
          );
      }

      if (recipientKey?.public_key) {
        // encryptMessage reads the File objects itself. Pre-encoding
        // them here made it crash with "file.arrayBuffer is not a
        // function" whenever an attachment was present.
        const envelope =
          await encryptMessage({
            recipientEmail:
              normalizedRecipient,
            subject: normalizedSubject,
            body: normalizedBody,
            attachments,
            recipientKey,
          });

        const formData =
          new FormData();

        formData.append(
          "recipient_email",
          normalizedRecipient
        );

        formData.append(
          "subject",
          "[SecureMailScope E2E] Encrypted message"
        );

        // Sent as a file part: plain multipart text fields are
        // limited to 1 MB by the backend framework, which rejected
        // envelopes carrying encrypted attachments.
        formData.append(
          "body_file",
          new Blob(
            [
              formatEnvelopeForEmail(
                envelope
              ),
            ],
            {
              type: "text/plain",
            }
          ),
          "securemailscope-envelope.txt"
        );

        const response =
          await fetch(
            `${API_BASE}/api/send/email`,
            {
              method: "POST",
              body: formData,
            }
          );

        const data =
          await response.json();

        if (!response.ok) {
          throw new Error(
            data.detail ||
              data.error ||
              data.message ||
              "Unable to send encrypted email."
          );
        }

        if (
          data.result?.status &&
          data.result.status !==
            "success"
        ) {
          throw new Error(
            data.result.message ||
              "Encrypted email submission failed."
          );
        }

        setSendResult({
          type: "success",
          message:
            "Encrypted SecureMailScope message submitted successfully.",
          data,
          e2e: {
            enabled: true,
            protocol:
              envelope.protocol,
            contentEncryption:
              envelope.content_encryption,
            keyEncryption:
              envelope.key_encryption,
            recipientKeyId:
              envelope.recipient_key_id,
            recipientFingerprint:
              envelope.recipient_key_fingerprint,
          },
        });

        setAttachments([]);

        return;
      }

      const sendStandard =
        window.confirm(
          "This recipient does not have a registered SecureMailScope encryption key.\n\nSecureMailScope cannot provide end-to-end encryption for this recipient.\n\nSend this message as a standard email without E2E encryption?"
        );

      if (!sendStandard) {
        setSendResult({
          type: "error",
          message:
            "Sending cancelled because end-to-end encryption is unavailable for this recipient.",
        });

        return;
      }

      const formData =
        new FormData();

      formData.append(
        "recipient_email",
        normalizedRecipient
      );

      formData.append(
        "subject",
        normalizedSubject
      );

      formData.append(
        "body",
        normalizedBody
      );

      attachments.forEach(
        (file) => {
          formData.append(
            "attachments",
            file,
            file.name
          );
        }
      );

      const response =
        await fetch(
          `${API_BASE}/api/send/email`,
          {
            method: "POST",
            body: formData,
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            data.error ||
            data.message ||
            "Unable to send email."
        );
      }

      if (
        data.result?.status &&
        data.result.status !==
          "success"
      ) {
        throw new Error(
          data.result.message ||
            "Email submission failed."
        );
      }

      setSendResult({
        type: "success",
        message:
          "Standard email submitted successfully. End-to-end encryption was not available for this recipient.",
        data,
        e2e: {
          enabled: false,
        },
      });

      setAttachments([]);
    } catch (error) {
      setSendResult({
        type: "error",
        message:
          error.message ||
          "Unable to send email.",
      });
    } finally {
      setSendLoading(false);
    }
  };

  const loadInbox = async () => {
    if (!mailAccount?.connected) {
      setInboxMessages([]);

      setInboxError(
        "Connect a mailbox before loading the inbox."
      );

      return;
    }

    setInboxLoading(true);
    setInboxError(null);

    try {
      const accountId =
        encodeURIComponent(
          mailAccount.account_id
        );

      const response =
        await fetch(
          `${API_BASE}/api/mailbox/inbox?account_id=${accountId}&limit=20`
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to load inbox."
        );
      }

      setInboxMessages(
        data.messages || []
      );

      if (
        data.integration ===
          "smtp_only" &&
        !data.messages?.length
      ) {
        setInboxError(
          data.message ||
            "Inbox retrieval is not available for this mailbox connection."
        );
      }
    } catch (error) {
      setInboxError(
        error.message ||
          "Unable to load inbox."
      );
    } finally {
      setInboxLoading(false);
    }
  };

  const openMessage = async (
    messageId
  ) => {
    if (
      !mailAccount?.account_id
    ) {
      return;
    }

    setMessageLoading(true);
    setInboxError(null);

    try {
      const accountId =
        encodeURIComponent(
          mailAccount.account_id
        );

      const response =
        await fetch(
          `${API_BASE}/api/mailbox/message/${encodeURIComponent(
            messageId
          )}?account_id=${accountId}`
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to open message."
        );
      }

      setSelectedMessage({
        ...data.message,
        analysis:
          data.analysis,
      });
    } catch (error) {
      setInboxError(
        error.message ||
          "Unable to open message."
      );
    } finally {
      setMessageLoading(false);
    }
  };

  // Effects are declared after the functions they call.
  // Data-fetch-on-mount pattern: the loaders set loading state.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadMailboxState();
  }, []);

  useEffect(() => {
    const senderEmail =
      mailAccount?.sender_email?.trim();

    if (
      !mailAccount?.connected ||
      !senderEmail
    ) {
      return;
    }

    registerIdentity(senderEmail)
      .then((result) => {
        setIdentityRegistration(
          result
        );
      })
      .catch((error) => {
        console.error(
          "Unable to register SecureMailScope encryption identity:",
          error
        );

        setIdentityRegistration({
          status: "error",
          email: senderEmail,
          message:
            error.message,
        });
      });
  }, [
    mailAccount?.connected,
    mailAccount?.sender_email,
  ]);

  useEffect(() => {
    const handleOAuthMessage = async (event) => {
      const apiOrigin =
        new URL(API_BASE).origin;

      if (
        event.origin !== apiOrigin &&
        event.origin !==
          apiOrigin.replace(
            "127.0.0.1",
            "localhost"
          )
      ) {
        return;
      }

      const message =
        event.data;

      if (
        !message ||
        message.type !==
          "securemailscope-oauth-result"
      ) {
        return;
      }

      // The callback page sends the provider inside result.
      const provider =
        message.result?.provider ||
        "";

      setOauthLoading("");
      setAccountError(null);

      const result =
        message.result ||
        {};

      if (
        result.status ===
        "success"
      ) {
        setAttachPanelOpen(false);
        setAddMailboxPanelOpen(false);
        setAttachSelectionId("");

        await refreshMailboxState();

        setAccountError(
          `${formatProviderName(
            provider
          )} account authorized and saved. Attach and connect it explicitly when you are ready.`
        );

        return;
      }

      setAccountError(
        result.message ||
          `${formatProviderName(
            provider
          )} authorization was not completed.`
      );
    };

    window.addEventListener(
      "message",
      handleOAuthMessage
    );

    return () => {
      window.removeEventListener(
        "message",
        handleOAuthMessage
      );
    };
  }, []);

  useEffect(() => {
    // When no mailbox is connected the inbox renders an empty list
    // (see InboxView props) instead of resetting state here.
    if (
      activeView === "inbox" &&
      mailAccount?.connected
    ) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      loadInbox();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    activeView,
    mailAccount?.connected,
    mailAccount?.account_id,
  ]);

  const openView = (view) => {
    setActiveView(view);

    if (view !== "inbox") {
      setSelectedMessage(null);
    }
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            S
          </div>

          <div>
            <h1>
              SecureMailScope
            </h1>

            <span>
              Secure email intelligence
            </span>
          </div>
        </div>

        <div className="status">
          <span className="status-dot" />
          Security engine online
        </div>
      </header>

      <main className="workspace">
        {activeView ===
          "compose" && (
          <ComposeView
            recipient={
              recipient
            }
            setRecipient={(value) => {
              setRecipient(value);

              // An assessment belongs to the recipient it was run
              // for. Keeping it after an edit showed the old
              // domain/E2E status next to the new address.
              if (assessment) {
                setAssessment(null);
                setSendResult(null);
              }
            }}
            subject={subject}
            setSubject={
              setSubject
            }
            body={body}
            setBody={setBody}
            attachments={
              attachments
            }
            handleAttachmentChange={
              handleAttachmentChange
            }
            removeAttachment={
              removeAttachment
            }
            attachmentTotalSize={
              getAttachmentTotalSize()
            }
            mailAccount={
              mailAccount
            }
            mailAccountLoading={
              mailAccountLoading
            }
            attachedMailAccounts={
              attachedMailAccounts
            }
            availableMailAccounts={
              availableMailAccounts
            }
            savedMailAccounts={
              savedMailAccounts
            }
            selectedAccountId={
              selectedAccountId
            }
            selectMailbox={
              selectMailbox
            }
            attachPanelOpen={
              attachPanelOpen
            }
            attachSelectionId={
              attachSelectionId
            }
            setAttachSelectionId={
              setAttachSelectionId
            }
            openAttachMailbox={
              openAttachMailbox
            }
            closeAttachMailbox={
              closeAttachMailbox
            }
            attachMailbox={
              attachMailbox
            }
            connectMailbox={
              connectMailbox
            }
            disconnectMailbox={
              disconnectMailbox
            }
            detachMailbox={
              detachMailbox
            }
            removeMailbox={
              removeMailbox
            }
            accountConnecting={
              accountConnecting
            }
            accountError={
              accountError
            }
            oauthLoading={
              oauthLoading
            }
            startOAuth={
              startOAuth
            }
            addMailboxPanelOpen={
              addMailboxPanelOpen
            }
            openAddMailbox={
              openAddMailbox
            }
            closeAddMailbox={
              closeAddMailbox
            }
            newMailboxEmail={
              newMailboxEmail
            }
            setNewMailboxEmail={
              setNewMailboxEmail
            }
            newMailboxUsername={
              newMailboxUsername
            }
            setNewMailboxUsername={
              setNewMailboxUsername
            }
            newMailboxPassword={
              newMailboxPassword
            }
            setNewMailboxPassword={
              setNewMailboxPassword
            }
            newMailboxHost={
              newMailboxHost
            }
            setNewMailboxHost={
              setNewMailboxHost
            }
            newMailboxPort={
              newMailboxPort
            }
            setNewMailboxPort={
              setNewMailboxPort
            }
            newMailboxSecurityMode={
              newMailboxSecurityMode
            }
            setNewMailboxSecurityMode={
              setNewMailboxSecurityMode
            }
            newMailboxProvider={
              newMailboxProvider
            }
            setNewMailboxProvider={
              setNewMailboxProvider
            }
            mailboxSaving={
              mailboxSaving
            }
            mailboxRemovingId={
              mailboxRemovingId
            }
            createMailbox={
              createMailbox
            }
            assessment={
              assessment
            }
            loading={loading}
            checkRecipient={
              checkRecipient
            }
            sendEmail={
              sendEmail
            }
            sendLoading={
              sendLoading
            }
            sendResult={
              sendResult
            }
          />
        )}

        {activeView ===
          "inbox" && (
          <InboxView
            messages={
              mailAccount?.connected
                ? inboxMessages
                : []
            }
            loading={
              inboxLoading
            }
            error={
              inboxError
            }
            selectedMessage={
              selectedMessage
            }
            messageLoading={
              messageLoading
            }
            loadInbox={
              loadInbox
            }
            openMessage={
              openMessage
            }
            closeMessage={() => {
              setSelectedMessage(
                null
              );
              setInboxError(null);
            }}
            mailAccount={
              mailAccount
            }
            identityRegistration={
              identityRegistration
            }
            onIdentityChanged={
              setIdentityRegistration
            }
          />
        )}

        {activeView ===
          "sent" && (
          <PlaceholderView
            eyebrow="SENT"
            title="Sent messages."
            description="Track submission and post-send security verification here."
          />
        )}

        {activeView ===
          "security" && (
          <PlaceholderView
            eyebrow="SECURITY"
            title="Security intelligence."
            description="Review cryptographic posture, transport evidence and security assessments."
          />
        )}

        {activeView ===
          "forensics" && (
          <PlaceholderView
            eyebrow="FORENSICS"
            title="Inspect the evidence."
            description="Analyze email files for authentication, transit security, HNDL and PQC signals."
          />
        )}
      </main>

      <WorkspaceNav
        activeView={
          activeView
        }
        setActiveView={
          openView
        }
      />
    </div>
  );
}

function ComposeView({
  recipient,
  setRecipient,
  subject,
  setSubject,
  body,
  setBody,
  attachments,
  handleAttachmentChange,
  removeAttachment,
  attachmentTotalSize,
  mailAccount,
  mailAccountLoading,
  attachedMailAccounts,
  availableMailAccounts,
  savedMailAccounts,
  selectedAccountId,
  selectMailbox,
  attachPanelOpen,
  attachSelectionId,
  setAttachSelectionId,
  openAttachMailbox,
  closeAttachMailbox,
  attachMailbox,
  connectMailbox,
  disconnectMailbox,
  detachMailbox,
  removeMailbox,
  accountConnecting,
  accountError,
  oauthLoading,
  startOAuth,
  addMailboxPanelOpen,
  openAddMailbox,
  closeAddMailbox,
  newMailboxEmail,
  setNewMailboxEmail,
  newMailboxUsername,
  setNewMailboxUsername,
  newMailboxPassword,
  setNewMailboxPassword,
  newMailboxHost,
  setNewMailboxHost,
  newMailboxPort,
  setNewMailboxPort,
  newMailboxSecurityMode,
  setNewMailboxSecurityMode,
  newMailboxProvider,
  setNewMailboxProvider,
  mailboxSaving,
  mailboxRemovingId,
  createMailbox,
  assessment,
  loading,
  checkRecipient,
  sendEmail,
  sendLoading,
  sendResult,
}) {
  const attachmentInputRef =
    useRef(null);

  const connected =
    Boolean(
      mailAccount?.connected
    );

  const selectedAttachedAccount =
    attachedMailAccounts.find(
      (account) =>
        account.account_id ===
        selectedAccountId
    );

  const attachedIds =
    new Set(
      attachedMailAccounts.map(
        (account) =>
          account.account_id
      )
    );

  const savedAccountsNotAttached =
    savedMailAccounts.filter(
      (account) =>
        !attachedIds.has(
          account.account_id
        )
    );

  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">
            SECURE SEND
          </span>

          <h2>
            Understand the destination
            before you send.
          </h2>

          <p>
            Assess the recipient domain,
            review observable security
            evidence, and make an
            informed decision before
            sending.
          </p>
        </div>
      </section>

      <section
        className="card"
        style={{
          marginBottom: "14px",
        }}
      >
        <div className="card-header">
          <div>
            <span className="section-label">
              MAILBOX
            </span>

            <h3>
              {connected
                ? "Connected sending account"
                : attachedMailAccounts.length >
                  0
                ? "Attached mailboxes"
                : "No mailbox attached"}
            </h3>
          </div>

          {connected && (
            <span className="live-badge">
              CONNECTED
            </span>
          )}
        </div>

        {mailAccountLoading ? (
          <div className="empty-state">
            <div className="shield">
              ⌁
            </div>

            <h4>
              Loading mailbox state
            </h4>

            <p>
              Checking saved and explicitly
              attached mailboxes.
            </p>
          </div>
        ) : (
          <>
            {attachedMailAccounts.length ===
              0 && (
              <div className="empty-state">
                <div className="shield">
                  ⌁
                </div>

                <h4>
                  No mailbox attached
                </h4>

                <p>
                  Attach a saved mailbox or
                  add a new mailbox when you
                  are ready. Nothing is
                  automatically selected or
                  connected.
                </p>

                <div
                  style={{
                    display: "flex",
                    gap: "8px",
                    flexWrap:
                      "wrap",
                    justifyContent:
                      "center",
                    marginTop:
                      "14px",
                  }}
                >
                  <button
                    className="assess-button"
                    type="button"
                    onClick={
                      openAttachMailbox
                    }
                    disabled={
                      accountConnecting ||
                      mailboxSaving ||
                      Boolean(
                        mailboxRemovingId
                      ) ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  >
                    + Attach saved mailbox
                  </button>

                  <button
                    className="assess-button"
                    type="button"
                    onClick={
                      openAddMailbox
                    }
                    disabled={
                      accountConnecting ||
                      mailboxSaving ||
                      Boolean(
                        mailboxRemovingId
                      ) ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  >
                    + Add mailbox
                  </button>
                </div>
              </div>
            )}

            {savedMailAccounts.length >
              0 && (
              <div
                className="security-findings"
                style={{
                  marginTop:
                    attachedMailAccounts.length >
                    0
                      ? "14px"
                      : "0",
                }}
              >
                <h4>
                  Saved mailboxes
                </h4>

                <p
                  className="security-source"
                  style={{
                    marginTop: "6px",
                    marginBottom:
                      "12px",
                  }}
                >
                  Saved connection details are
                  kept for later use. Credentials
                  and OAuth tokens are never
                  displayed here.
                </p>

                <div
                  style={{
                    display: "grid",
                    gap: "8px",
                  }}
                >
                  {savedMailAccounts.map(
                    (account) => {
                      const isAttached =
                        attachedIds.has(
                          account.account_id
                        );

                      const isConnected =
                        connected &&
                        mailAccount.account_id ===
                          account.account_id;

                      const isRemoving =
                        mailboxRemovingId ===
                        account.account_id;

                      return (
                        <div
                          key={
                            account.account_id
                          }
                          style={{
                            width: "100%",
                            padding:
                              "13px 14px",
                            borderRadius:
                              "10px",
                            border:
                              isConnected
                                ? "2px solid currentColor"
                                : "1px solid currentColor",
                            background:
                              "transparent",
                            opacity:
                              isRemoving
                                ? 0.6
                                : 1,
                          }}
                        >
                          <div
                            style={{
                              display:
                                "flex",
                              justifyContent:
                                "space-between",
                              alignItems:
                                "center",
                              gap: "12px",
                            }}
                          >
                            <div
                              style={{
                                minWidth: 0,
                                flex: 1,
                              }}
                            >
                              <strong
                                style={{
                                  display:
                                    "block",
                                  overflow:
                                    "hidden",
                                  textOverflow:
                                    "ellipsis",
                                  whiteSpace:
                                    "nowrap",
                                }}
                              >
                                {
                                  account.sender_email
                                }
                              </strong>

                              <span
                                className="security-source"
                                style={{
                                  display:
                                    "block",
                                  marginTop:
                                    "3px",
                                }}
                              >
                                {account.provider ||
                                  formatAuthenticationLabel(
                                    account
                                  )}{" "}
                                ·{" "}
                                {account.smtp
                                  ?.host ||
                                  "Provider authorization"}
                                {account.smtp
                                  ?.port
                                  ? `:${account.smtp.port}`
                                  : ""}
                              </span>
                            </div>

                            <span
                              className={
                                isConnected
                                  ? "positive"
                                  : isAttached
                                  ? "positive"
                                  : "neutral"
                              }
                              style={{
                                flexShrink:
                                  0,
                              }}
                            >
                              {isConnected
                                ? "Connected"
                                : isAttached
                                ? "Attached"
                                : "Saved"}
                            </span>
                          </div>

                          <div
                            style={{
                              display:
                                "flex",
                              gap: "8px",
                              flexWrap:
                                "wrap",
                              marginTop:
                                "10px",
                            }}
                          >
                            {isAttached ? (
                              <>
                                <button
                                  type="button"
                                  className="assess-button"
                                  onClick={() =>
                                    connectMailbox(
                                      account.account_id
                                    )
                                  }
                                  disabled={
                                    accountConnecting ||
                                    mailboxSaving ||
                                    mailboxRemovingId ||
                                    isConnected ||
                                    Boolean(
                                      oauthLoading
                                    )
                                  }
                                  style={{
                                    flex: 1,
                                  }}
                                >
                                  {isConnected
                                    ? "Connected"
                                    : accountConnecting
                                    ? "Connecting..."
                                    : "Use this account"}
                                </button>

                                {!isConnected && (
                                  <button
                                    type="button"
                                    className="assess-button"
                                    onClick={() =>
                                      detachMailbox(
                                        account.account_id
                                      )
                                    }
                                    disabled={
                                      accountConnecting ||
                                      mailboxSaving ||
                                      Boolean(
                                        mailboxRemovingId
                                      ) ||
                                      Boolean(
                                        oauthLoading
                                      )
                                    }
                                  >
                                    Detach
                                  </button>
                                )}
                              </>
                            ) : (
                              <button
                                type="button"
                                className="assess-button"
                                onClick={() =>
                                  openAttachMailbox()
                                    .then(
                                      () =>
                                        setAttachSelectionId(
                                          account.account_id
                                        )
                                    )
                                }
                                disabled={
                                  accountConnecting ||
                                  mailboxSaving ||
                                  Boolean(
                                    mailboxRemovingId
                                  ) ||
                                  Boolean(
                                    oauthLoading
                                  )
                                }
                                style={{
                                  flex: 1,
                                }}
                              >
                                Attach
                              </button>
                            )}

                            <button
                              type="button"
                              className="assess-button"
                              onClick={() =>
                                removeMailbox(
                                  account.account_id,
                                  account.sender_email
                                )
                              }
                              disabled={
                                accountConnecting ||
                                mailboxSaving ||
                                Boolean(
                                  mailboxRemovingId
                                ) ||
                                isConnected ||
                                Boolean(
                                  oauthLoading
                                )
                              }
                            >
                              {isRemoving
                                ? "Removing..."
                                : "Remove"}
                            </button>
                          </div>

                          {isConnected && (
                            <button
                              type="button"
                              className="assess-button"
                              onClick={
                                disconnectMailbox
                              }
                              disabled={
                                accountConnecting ||
                                mailboxSaving ||
                                Boolean(
                                  mailboxRemovingId
                                )
                              }
                              style={{
                                width:
                                  "100%",
                                marginTop:
                                  "8px",
                              }}
                            >
                              Disconnect active mailbox
                            </button>
                          )}
                        </div>
                      );
                    }
                  )}
                </div>

                {savedAccountsNotAttached.length ===
                  0 &&
                  attachedMailAccounts.length >
                    0 && (
                    <p
                      className="security-source"
                      style={{
                        marginTop:
                          "10px",
                      }}
                    >
                      All saved mailboxes are
                      currently attached or
                      connected.
                    </p>
                  )}
              </div>
            )}

            {attachedMailAccounts.length >
              0 && (
              <>
                <div className="security-findings">
                  <h4>
                    Attached mailboxes
                  </h4>

                  <p
                    className="security-source"
                    style={{
                      marginTop: "6px",
                      marginBottom:
                        "12px",
                    }}
                  >
                    Choose which attached
                    account should be used.
                    Accounts can belong to
                    the same domain or different
                    domains.
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gap: "8px",
                    }}
                  >
                    {attachedMailAccounts.map(
                      (account) => {
                        const isSelected =
                          selectedAccountId ===
                          account.account_id;

                        const isConnected =
                          connected &&
                          mailAccount.account_id ===
                            account.account_id;

                        return (
                          <div
                            key={
                              account.account_id
                            }
                            style={{
                              width:
                                "100%",
                              padding:
                                "13px 14px",
                              borderRadius:
                                "10px",
                              border:
                                isConnected ||
                                isSelected
                                  ? "2px solid currentColor"
                                  : "1px solid currentColor",
                              background:
                                "transparent",
                              opacity:
                                accountConnecting
                                  ? 0.65
                                  : 1,
                            }}
                          >
                            <div
                              style={{
                                display:
                                  "flex",
                                justifyContent:
                                  "space-between",
                                alignItems:
                                  "center",
                                gap:
                                  "12px",
                              }}
                            >
                              <button
                                type="button"
                                onClick={() =>
                                  selectMailbox(
                                    account.account_id
                                  )
                                }
                                disabled={
                                  accountConnecting ||
                                  Boolean(
                                    mailboxRemovingId
                                  )
                                }
                                style={{
                                  flex: 1,
                                  minWidth:
                                    0,
                                  border:
                                    "none",
                                  background:
                                    "transparent",
                                  padding: 0,
                                  textAlign:
                                    "left",
                                  cursor:
                                    accountConnecting
                                      ? "default"
                                      : "pointer",
                                  font:
                                    "inherit",
                                }}
                              >
                                <strong
                                  style={{
                                    display:
                                      "block",
                                    overflow:
                                      "hidden",
                                    textOverflow:
                                      "ellipsis",
                                    whiteSpace:
                                      "nowrap",
                                  }}
                                >
                                  {
                                    account.sender_email
                                  }
                                </strong>

                                <span
                                  className="security-source"
                                  style={{
                                    display:
                                      "block",
                                    marginTop:
                                      "3px",
                                  }}
                                >
                                  {account.provider ||
                                    formatAuthenticationLabel(
                                      account
                                    )}{" "}
                                  ·{" "}
                                  {account.smtp
                                    ?.host ||
                                    "Provider authorization"}
                                  {account.smtp
                                    ?.port
                                    ? `:${account.smtp.port}`
                                    : ""}
                                </span>
                              </button>

                              <span
                                className={
                                  isConnected ||
                                  isSelected
                                    ? "positive"
                                    : "neutral"
                                }
                                style={{
                                  flexShrink:
                                    0,
                                }}
                              >
                                {isConnected
                                  ? "Connected"
                                  : isSelected
                                  ? "Selected"
                                  : "Attached"}
                              </span>
                            </div>

                            <div
                              style={{
                                display:
                                  "flex",
                                gap: "8px",
                                marginTop:
                                  "10px",
                              }}
                            >
                              <button
                                type="button"
                                className="assess-button"
                                onClick={() =>
                                  connectMailbox(
                                    account.account_id
                                  )
                                }
                                disabled={
                                  accountConnecting ||
                                  isConnected ||
                                  Boolean(
                                    mailboxRemovingId
                                  )
                                }
                                style={{
                                  flex: 1,
                                }}
                              >
                                {isConnected
                                  ? "Connected"
                                  : accountConnecting
                                  ? "Connecting..."
                                  : "Use this account"}
                              </button>

                              {!isConnected && (
                                <button
                                  type="button"
                                  className="assess-button"
                                  onClick={() =>
                                    detachMailbox(
                                      account.account_id
                                    )
                                  }
                                  disabled={
                                    accountConnecting ||
                                    Boolean(
                                      mailboxRemovingId
                                    )
                                  }
                                >
                                  Detach
                                </button>
                              )}
                            </div>
                          </div>
                        );
                      }
                    )}
                  </div>
                </div>

                {accountError && (
                  <div
                    className="error-box"
                    style={{
                      marginTop: "12px",
                    }}
                  >
                    {accountError}
                  </div>
                )}

                <div
                  style={{
                    display: "grid",
                    gap: "8px",
                    marginTop: "14px",
                  }}
                >
                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      openAttachMailbox
                    }
                    disabled={
                      accountConnecting ||
                      mailboxSaving ||
                      Boolean(
                        mailboxRemovingId
                      ) ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    style={{
                      width: "100%",
                    }}
                  >
                    + Attach saved mailbox
                  </button>

                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      openAddMailbox
                    }
                    disabled={
                      accountConnecting ||
                      mailboxSaving ||
                      Boolean(
                        mailboxRemovingId
                      ) ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    style={{
                      width: "100%",
                    }}
                  >
                    + Add new mailbox
                  </button>
                </div>

                {connected && (
                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      disconnectMailbox
                    }
                    disabled={
                      accountConnecting ||
                      Boolean(
                        mailboxRemovingId
                      )
                    }
                    style={{
                      width: "100%",
                      marginTop:
                        "8px",
                    }}
                  >
                    Disconnect active mailbox
                  </button>
                )}

                {selectedAttachedAccount && (
                  <p
                    className="security-source"
                    style={{
                      marginTop: "8px",
                    }}
                  >
                    Selected:{" "}
                    {
                      selectedAttachedAccount.sender_email
                    }
                    . Selection alone does not
                    connect the mailbox.
                  </p>
                )}
              </>
            )}

            {accountError &&
              attachedMailAccounts.length ===
                0 && (
                <div
                  className="error-box"
                  style={{
                    marginTop: "12px",
                  }}
                >
                  {accountError}
                </div>
              )}

            {addMailboxPanelOpen && (
              <div
                id="add-mailbox-panel"
                className="security-findings"
                style={{
                  marginTop: "14px",
                }}
              >
                <div
                  className="card-header"
                  style={{
                    padding: 0,
                    marginBottom:
                      "12px",
                  }}
                >
                  <div>
                    <span className="section-label">
                      ADD MAILBOX
                    </span>

                    <h4>
                      Add a sending account
                    </h4>
                  </div>
                </div>

                <p
                  className="security-source"
                  style={{
                    marginTop: 0,
                    marginBottom:
                      "14px",
                  }}
                >
                  Choose a provider sign-in for
                  Google or Microsoft, or configure
                  a custom SMTP server. Provider
                  authorization saves the mailbox
                  but does not attach or connect it.
                </p>

                <div
                  style={{
                    display: "grid",
                    gap: "8px",
                    marginBottom:
                      "16px",
                  }}
                >
                  <button
                    type="button"
                    className="assess-button"
                    onClick={() =>
                      startOAuth(
                        "google"
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      accountConnecting ||
                      Boolean(
                        mailboxRemovingId
                      ) ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    style={{
                      width: "100%",
                    }}
                  >
                    {oauthLoading ===
                    "google"
                      ? "Opening Google authorization..."
                      : "Continue with Google"}
                  </button>

                  <button
                    type="button"
                    className="assess-button"
                    onClick={() =>
                      startOAuth(
                        "microsoft"
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      accountConnecting ||
                      Boolean(
                        mailboxRemovingId
                      ) ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    style={{
                      width: "100%",
                    }}
                  >
                    {oauthLoading ===
                    "microsoft"
                      ? "Opening Microsoft authorization..."
                      : "Continue with Microsoft"}
                  </button>
                </div>

                <div
                  className="security-source"
                  style={{
                    textAlign:
                      "center",
                    marginBottom:
                      "14px",
                  }}
                >
                  — or configure a custom SMTP mailbox —
                </div>

                <label>
                  Email address

                  <input
                    type="email"
                    placeholder="user@example.com"
                    value={
                      newMailboxEmail
                    }
                    onChange={(event) =>
                      setNewMailboxEmail(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    autoComplete="email"
                  />
                </label>

                <label>
                  SMTP username

                  <input
                    type="text"
                    placeholder="SMTP username"
                    value={
                      newMailboxUsername
                    }
                    onChange={(event) =>
                      setNewMailboxUsername(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    autoComplete="username"
                  />
                </label>

                <label>
                  Server credential

                  <input
                    type="password"
                    placeholder="Credential required by the custom SMTP server"
                    value={
                      newMailboxPassword
                    }
                    onChange={(event) =>
                      setNewMailboxPassword(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    autoComplete="new-password"
                  />
                </label>

                <label>
                  SMTP host

                  <input
                    type="text"
                    placeholder="smtp.example.com"
                    value={
                      newMailboxHost
                    }
                    onChange={(event) =>
                      setNewMailboxHost(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  />
                </label>

                <label>
                  SMTP port

                  <input
                    type="number"
                    min="1"
                    max="65535"
                    placeholder="587"
                    value={
                      newMailboxPort
                    }
                    onChange={(event) =>
                      setNewMailboxPort(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  />
                </label>

                <label>
                  Security

                  <select
                    value={
                      newMailboxSecurityMode
                    }
                    onChange={(event) =>
                      setNewMailboxSecurityMode(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  >
                    <option value="starttls">
                      STARTTLS
                    </option>

                    <option value="tls">
                      TLS / SSL
                    </option>

                    <option value="none">
                      None
                    </option>
                  </select>
                </label>

                <label>
                  Provider label (optional)

                  <input
                    type="text"
                    placeholder="Company / Custom / Other"
                    value={
                      newMailboxProvider
                    }
                    onChange={(event) =>
                      setNewMailboxProvider(
                        event.target.value
                      )
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  />
                </label>

                {accountError && (
                  <div
                    className="error-box"
                    style={{
                      marginTop: "12px",
                    }}
                  >
                    {accountError}
                  </div>
                )}

                <div
                  style={{
                    display: "flex",
                    gap: "10px",
                    marginTop: "14px",
                  }}
                >
                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      createMailbox
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    style={{
                      flex: 1,
                    }}
                  >
                    {mailboxSaving
                      ? "Saving..."
                      : "Save custom SMTP mailbox"}
                  </button>

                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      closeAddMailbox
                    }
                    disabled={
                      mailboxSaving ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  >
                    Cancel
                  </button>
                </div>

                <p
                  className="security-source"
                  style={{
                    marginTop:
                      "8px",
                  }}
                >
                  Google and Microsoft accounts use
                  provider authorization. Custom SMTP
                  accounts use the credential required
                  by that server. Saved credentials are
                  never displayed. Saving does not
                  attach or activate the mailbox.
                </p>
              </div>
            )}

            {attachPanelOpen && (
              <div
                className="security-findings"
                style={{
                  marginTop: "14px",
                }}
              >
                <div
                  className="card-header"
                  style={{
                    padding: 0,
                    marginBottom:
                      "12px",
                  }}
                >
                  <div>
                    <span className="section-label">
                      ATTACH MAILBOX
                    </span>

                    <h4>
                      Choose an account to attach
                    </h4>
                  </div>
                </div>

                {availableMailAccounts.length ===
                  0 ? (
                  <div className="unknown-box">
                    <strong>
                      No additional mailboxes
                      available
                    </strong>

                    <p>
                      There are no saved
                      mailboxes available to
                      attach. Add a new mailbox
                      if you need another
                      connection.
                    </p>
                  </div>
                ) : (
                  <div
                    style={{
                      display:
                        "grid",
                      gap: "8px",
                    }}
                  >
                    {availableMailAccounts.map(
                      (account) => {
                        const selected =
                          attachSelectionId ===
                          account.account_id;

                        return (
                          <button
                            key={
                              account.account_id
                            }
                            type="button"
                            onClick={() =>
                              setAttachSelectionId(
                                account.account_id
                              )
                            }
                            disabled={
                              accountConnecting ||
                              Boolean(
                                mailboxRemovingId
                              ) ||
                              Boolean(
                                oauthLoading
                              )
                            }
                            style={{
                              width:
                                "100%",
                              textAlign:
                                "left",
                              padding:
                                "13px 14px",
                              borderRadius:
                                "10px",
                              border:
                                selected
                                  ? "2px solid currentColor"
                                  : "1px solid currentColor",
                              background:
                                "transparent",
                              cursor:
                                accountConnecting
                                  ? "default"
                                  : "pointer",
                              font:
                                "inherit",
                              opacity:
                                accountConnecting
                                  ? 0.65
                                  : 1,
                            }}
                          >
                            <div
                              style={{
                                display:
                                  "flex",
                                justifyContent:
                                  "space-between",
                                alignItems:
                                  "center",
                                gap:
                                  "12px",
                              }}
                            >
                              <div
                                style={{
                                  minWidth:
                                    0,
                                }}
                              >
                                <strong
                                  style={{
                                    display:
                                      "block",
                                    overflow:
                                      "hidden",
                                    textOverflow:
                                      "ellipsis",
                                    whiteSpace:
                                      "nowrap",
                                  }}
                                >
                                  {
                                    account.sender_email
                                  }
                                </strong>

                                <span
                                  className="security-source"
                                  style={{
                                    display:
                                      "block",
                                    marginTop:
                                      "3px",
                                  }}
                                >
                                  {account.provider ||
                                    formatAuthenticationLabel(
                                      account
                                    )}{" "}
                                  ·{" "}
                                  {account.smtp
                                    ?.host ||
                                    "Provider authorization"}
                                  {account.smtp
                                    ?.port
                                    ? `:${account.smtp.port}`
                                    : ""}
                                </span>
                              </div>

                              <span
                                className={
                                  selected
                                    ? "positive"
                                    : "neutral"
                                }
                                style={{
                                  flexShrink:
                                    0,
                                }}
                              >
                                {selected
                                  ? "Selected"
                                  : "Select"}
                              </span>
                            </div>
                          </button>
                        );
                      }
                    )}
                  </div>
                )}

                <div
                  style={{
                    display:
                      "flex",
                    gap: "10px",
                    marginTop:
                      "14px",
                  }}
                >
                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      attachMailbox
                    }
                    disabled={
                      accountConnecting ||
                      !attachSelectionId ||
                      Boolean(
                        mailboxRemovingId
                      ) ||
                      Boolean(
                        oauthLoading
                      )
                    }
                    style={{
                      flex: 1,
                    }}
                  >
                    {accountConnecting
                      ? "Attaching..."
                      : "Attach selected"}
                  </button>

                  <button
                    type="button"
                    className="assess-button"
                    onClick={
                      closeAttachMailbox
                    }
                    disabled={
                      accountConnecting ||
                      Boolean(
                        oauthLoading
                      )
                    }
                  >
                    Cancel
                  </button>
                </div>

                <button
                  type="button"
                  className="assess-button"
                  onClick={
                    openAddMailbox
                  }
                  disabled={
                    accountConnecting ||
                    mailboxSaving ||
                    Boolean(
                      mailboxRemovingId
                    ) ||
                    Boolean(
                      oauthLoading
                    )
                  }
                  style={{
                    width: "100%",
                    marginTop:
                      "8px",
                  }}
                >
                  + Add new mailbox
                </button>

                <p
                  className="security-source"
                  style={{
                    marginTop:
                      "8px",
                  }}
                >
                  Attaching only adds the mailbox
                  to this workspace. It does not
                  activate, authenticate, or send
                  through it.
                </p>
              </div>
            )}

            {!attachPanelOpen &&
              !addMailboxPanelOpen &&
              attachedMailAccounts.length ===
                0 &&
              !accountError && (
                <p
                  className="security-source"
                  style={{
                    marginTop:
                      "8px",
                    textAlign:
                      "center",
                  }}
                >
                  No mailbox is accessed until
                  you explicitly attach and
                  connect one.
                </p>
              )}
          </>
        )}
      </section>

      <section className="compose-grid">
        <div className="card compose-card">
          <div className="card-header">
            <div>
              <span className="section-label">
                MESSAGE
              </span>

              <h3>
                Compose email
              </h3>
            </div>

            <span className="draft">
              Draft
            </span>
          </div>

          <label>
            Recipient

            <input
              type="email"
              placeholder="recipient@example.com"
              value={recipient}
              onChange={(e) =>
                setRecipient(
                  e.target.value
                )
              }
            />
          </label>

          <button
            className="assess-button"
            onClick={
              checkRecipient
            }
            disabled={
              loading ||
              !recipient.trim()
            }
          >
            {loading
              ? "Assessing..."
              : "Check recipient security"}
          </button>

          <label>
            Subject

            <input
              type="text"
              placeholder="Subject"
              value={subject}
              onChange={(e) =>
                setSubject(
                  e.target.value
                )
              }
            />
          </label>

          <label>
            Message

            <textarea
              placeholder="Write your message..."
              value={body}
              onChange={(e) =>
                setBody(
                  e.target.value
                )
              }
            />
          </label>

          <div
            style={{
              marginTop:
                "14px",
            }}
          >
            <input
              ref={
                attachmentInputRef
              }
              type="file"
              multiple
              onChange={
                handleAttachmentChange
              }
              style={{
                display: "none",
              }}
            />

            <button
              type="button"
              className="assess-button"
              onClick={() =>
                attachmentInputRef.current?.click()
              }
              disabled={
                sendLoading
              }
            >
              Add attachments
            </button>

            <p
              className="security-source"
              style={{
                marginTop:
                  "8px",
              }}
            >
              Optional files · Maximum total
              size 10 MB
            </p>

            {attachments.length >
              0 && (
              <div
                className="security-findings"
                style={{
                  marginTop:
                    "12px",
                }}
              >
                <h4>
                  Attachments (
                  {
                    attachments.length
                  }
                  )
                </h4>

                {attachments.map(
                  (
                    file,
                    index
                  ) => (
                    <div
                      className="security-row"
                      key={`${file.name}-${file.size}-${index}`}
                    >
                      <span
                        style={{
                          minWidth:
                            0,
                          overflow:
                            "hidden",
                          textOverflow:
                            "ellipsis",
                          whiteSpace:
                            "nowrap",
                          paddingRight:
                            "10px",
                        }}
                      >
                        {
                          file.name
                        }
                      </span>

                      <span
                        className="neutral"
                        style={{
                          display:
                            "flex",
                          alignItems:
                            "center",
                          gap: "8px",
                          flexShrink:
                            0,
                        }}
                      >
                        {formatFileSize(
                          file.size
                        )}

                        <button
                          type="button"
                          onClick={() =>
                            removeAttachment(
                              index
                            )
                          }
                          disabled={
                            sendLoading
                          }
                          style={{
                            border:
                              "none",
                            background:
                              "transparent",
                            cursor:
                              sendLoading
                                ? "default"
                                : "pointer",
                            padding:
                              "2px 4px",
                            font:
                              "inherit",
                          }}
                        >
                          Remove
                        </button>
                      </span>
                    </div>
                  )
                )}

                <p
                  className="security-source"
                  style={{
                    marginTop:
                      "8px",
                  }}
                >
                  Total:{" "}
                  {formatFileSize(
                    attachmentTotalSize
                  )}{" "}
                  / 10 MB
                </p>
              </div>
            )}

            {/* SecurityReview (which normally shows sendResult) only
                mounts after an assessment, so errors such as the
                attachment size limit were invisible before that. */}
            {!assessment &&
              sendResult?.type ===
                "error" && (
                <div
                  className="error-box"
                  style={{
                    marginTop:
                      "12px",
                  }}
                >
                  {sendResult.message}
                </div>
              )}
          </div>
        </div>

        <div>
          <SecurityPanel
            assessment={
              assessment
            }
            loading={loading}
          />

          {assessment &&
            !assessment.error &&
            !loading && (
              <SecurityReview
                assessment={
                  assessment
                }
                mailAccount={
                  mailAccount
                }
                mailAccountLoading={
                  mailAccountLoading
                }
                recipient={
                  recipient
                }
                subject={
                  subject
                }
                body={body}
                attachments={
                  attachments
                }
                sendEmail={
                  sendEmail
                }
                sendLoading={
                  sendLoading
                }
                sendResult={
                  sendResult
                }
                formatDecision={
                  formatDecision
                }
                formatAuthenticationLabel={
                  formatAuthenticationLabel
                }
                formatFileSize={
                  formatFileSize
                }
              />
            )}
        </div>
      </section>
    </>
  );
}

function SecurityPanel({
  assessment,
  loading,
}) {
  return (
    <div className="card security-card">
      <div className="card-header">
        <div>
          <span className="section-label">
            SECURITY CENTER
          </span>

          <h3>
            Recipient posture
          </h3>
        </div>

        {assessment &&
          !assessment.error && (
            <span className="live-badge">
              LIVE
            </span>
          )}
      </div>

      {loading && (
        <div className="empty-state">
          <div className="shield">
            ⌁
          </div>

          <h4>
            Assessing destination
          </h4>

          <p>
            Inspecting observable DNS,
            mail transport and
            cryptographic signals.
          </p>
        </div>
      )}

      {!loading &&
        !assessment && (
          <div className="empty-state">
            <div className="shield">
              ⌁
            </div>

            <h4>
              Waiting for assessment
            </h4>

            <p>
              Enter a recipient and
              check its domain to see
              observable security
              controls.
            </p>
          </div>
        )}

      {!loading &&
        assessment?.error && (
          <div className="error-box">
            {assessment.error}
          </div>
        )}

      {!loading &&
        assessment &&
        !assessment.error && (
          <AssessmentContent
            assessment={
              assessment
            }
          />
        )}
    </div>
  );
}

function AssessmentContent({
  assessment,
}) {
  const risk =
    assessment.risk;

  const pqc =
    assessment.security?.pqc;

  const observability =
    assessment.pre_send
      ?.observability;

  return (
    <>
      <div className="risk-panel">
        <div>
          <span>
            Risk posture
          </span>

          <strong>
            {risk?.risk_level ||
              "Unknown"}
          </strong>
        </div>

        <div className="risk-score">
          {risk?.score ?? "—"}
        </div>
      </div>

      <div className="metrics">
        <Metric
          label="Confidence"
          value={
            risk?.confidence ||
            "Unknown"
          }
        />

        <Metric
          label="Observability"
          value={
            risk?.observability ||
            "Unknown"
          }
        />

        <Metric
          label="PQC readiness"
          value={
            pqc?.readiness ||
            "Unknown"
          }
        />
      </div>

      <div className="decision">
        <span>
          Pre-send decision
        </span>

        <strong>
          {formatDecision(
            assessment.pre_send
              ?.decision
          )}
        </strong>
      </div>

      <div className="controls">
        <SecurityRow
          label="MTA-STS"
          value={formatMtaStsMode(
            getMtaStsMode(
              assessment
            )
          )}
          positive={
            getMtaStsMode(
              assessment
            ) === "enforce"
          }
        />

        <SecurityRow
          label="SMTP transport"
          value={
            observability?.smtp_unreachable_hosts >
              0 ||
            observability?.smtp_unobserved_hosts >
              0
              ? "Not observable"
              : "Observed"
          }
        />

        <SecurityRow
          label="STARTTLS"
          value={
            observability?.starttls_unobserved_hosts >
            0
              ? "Not observable"
              : "Observed"
          }
        />

        <SecurityRow
          label="TLS handshake"
          value={
            observability?.tls_unobserved_hosts >
            0
              ? "Not observable"
              : "Observed"
          }
        />
      </div>

      {assessment.pre_send
        ?.unknowns?.length >
        0 && (
        <div className="unknown-box">
          <strong>
            What could not be verified
          </strong>

          <p>
            Some transport properties
            could not be observed from
            the current assessment
            environment.
          </p>
        </div>
      )}

      {assessment.recommendations
        ?.length > 0 && (
        <div className="recommendation">
          <span>
            RECOMMENDATION
          </span>

          <strong>
            {
              assessment
                .recommendations[0]
                .title
            }
          </strong>

          <p>
            {
              assessment
                .recommendations[0]
                .why_it_matters
            }
          </p>
        </div>
      )}
    </>
  );
}


function InboxView({
  messages,
  loading,
  error,
  selectedMessage,
  messageLoading,
  loadInbox,
  openMessage,
  closeMessage,
  mailAccount,
  identityRegistration,
  onIdentityChanged,
}) {
  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">
            INBOX
          </span>

          <h2>
            Your secure inbox.
          </h2>

          <p>
            Incoming messages can be
            inspected and assessed for
            observable security signals.
          </p>
        </div>
      </section>

      {mailAccount?.connected &&
        mailAccount.sender_email && (
          <E2EIdentityPanel
            email={
              mailAccount.sender_email
            }
            registration={
              identityRegistration
            }
            onChanged={
              onIdentityChanged
            }
          />
        )}

      {messageLoading && (
        <div className="unknown-box">
          <strong>
            Opening message...
          </strong>

          <p>
            Retrieving the full message
            from the mail provider.
          </p>
        </div>
      )}

      {selectedMessage ? (
        <MessageView
          message={
            selectedMessage
          }
          onBack={
            closeMessage
          }
        />
      ) : (
        <section className="card">
          <div className="card-header">
            <div>
              <span className="section-label">
                MAILBOX
              </span>

              <h3>
                {loading
                  ? "Loading messages..."
                  : `${messages.length} message${
                      messages.length ===
                      1
                        ? ""
                        : "s"
                    }`}
              </h3>
            </div>

            {mailAccount?.connected && (
              <button
                className="assess-button"
                onClick={
                  loadInbox
                }
                disabled={
                  loading
                }
              >
                {loading
                  ? "Refreshing..."
                  : "Refresh"}
              </button>
            )}
          </div>

          {!mailAccount?.connected && (
            <div className="unknown-box">
              <strong>
                No mailbox connected
              </strong>

              <p>
                Attach and connect a
                mailbox from the Compose
                workspace before
                accessing mailbox data.
              </p>
            </div>
          )}

          {error && (
            <div className="error-box">
              {error}
            </div>
          )}

          {mailAccount?.connected &&
            loading && (
              <div className="empty-state">
                <div className="shield">
                  ⌁
                </div>

                <h4>
                  Loading inbox
                </h4>

                <p>
                  Retrieving messages from
                  the connected mail provider.
                </p>
              </div>
            )}

          {mailAccount?.connected &&
            !loading &&
            !error &&
            messages.length ===
              0 && (
              <div className="empty-state">
                <div className="shield">
                  ⌁
                </div>

                <h4>
                  No messages
                </h4>

                <p>
                  No messages are available
                  through the current
                  mailbox integration.
                </p>
              </div>
            )}

          {mailAccount?.connected &&
            !loading &&
            messages.length >
              0 && (
              <div className="inbox-list">
                {messages.map(
                  (message) => (
                    <button
                      key={
                        message.id
                      }
                      className="inbox-message"
                      disabled={
                        messageLoading
                      }
                      onClick={() =>
                        openMessage(
                          message.id
                        )
                      }
                    >
                      <div className="inbox-message-main">
                        <strong>
                          {
                            message.sender
                          }
                        </strong>

                        <span>
                          {
                            message.subject
                          }
                        </span>

                        <p>
                          {
                            message.preview
                          }
                        </p>
                      </div>

                      <div className="inbox-message-meta">
                        <span>
                          {formatDate(
                            message.received_at
                          )}
                        </span>

                        {message.e2e
                          ?.detected && (
                          <span className="e2e-badge">
                            E2E encrypted
                          </span>
                        )}

                        <span className="live-badge">
                          {
                            message.provider
                          }
                        </span>
                      </div>
                    </button>
                  )
                )}
              </div>
            )}
        </section>
      )}
    </>
  );
}

function MessageView({
  message,
  onBack,
}) {
  const [decryptedMessage, setDecryptedMessage] =
    useState(null);

  const [decrypting, setDecrypting] =
    useState(false);

  const [decryptError, setDecryptError] =
    useState(null);

  const [encryptedEnvelope, setEncryptedEnvelope] =
    useState(null);

  const analysis =
    message?.analysis;

  const security =
    analysis?.security;

  const authentication =
    security?.authentication;

  const summary =
    security?.summary;

  const risk =
    analysis?.risk;

  const hndl =
    analysis?.hndl;

  useEffect(() => {
    let cancelled = false;

    const decryptIfNeeded = async () => {
      setDecryptedMessage(null);
      setDecryptError(null);
      setEncryptedEnvelope(null);

      // extractEnvelope accepts the original raw-JSON body and the
      // armored body, and tolerates text added or re-wrapped by mail
      // clients. JSON.parse(body) failed on anything but a bare
      // envelope, so the receiver saw the ciphertext.
      const parsed =
        extractEnvelope(
          message?.body
        ) ||
        extractEnvelope(
          message?.html_body
        );

      if (!parsed) {
        return;
      }

      if (
        parsed?.version !== 1 ||
        parsed?.content_encryption !==
          "AES-256-GCM" ||
        parsed?.key_encryption !==
          "RSA-OAEP-256"
      ) {
        setDecryptError(
          "This SecureMailScope message uses an unsupported encryption format."
        );

        return;
      }

      setEncryptedEnvelope(parsed);
      setDecrypting(true);

      try {
        const recipientEmail =
          typeof parsed?.recipient ===
          "string"
            ? parsed.recipient.trim().toLowerCase()
            : "";

        if (!recipientEmail) {
          throw new Error(
            "Encrypted message is missing its recipient email address."
          );
        }

        const plaintext =
          await decryptMessage(
            parsed,
            recipientEmail
          );

        if (cancelled) {
          return;
        }

        setDecryptedMessage(
          plaintext
        );
      } catch (error) {
        if (cancelled) {
          return;
        }

        setDecryptError(
          error?.message ||
          "Unable to decrypt this SecureMailScope message with the local recipient key."
        );
      } finally {
        if (!cancelled) {
          setDecrypting(false);
        }
      }
    };

    decryptIfNeeded();

    return () => {
      cancelled = true;
    };
  }, [message]);

  const displaySubject =
    decryptedMessage?.subject ||
    (encryptedEnvelope
      ? "Encrypted SecureMailScope message"
      : message?.subject ||
        "Untitled message");

  const displayBody =
    decryptedMessage?.body ||
    (encryptedEnvelope
      ? ""
      : message?.body ||
        "No message body available.");

  const decryptedAttachments =
    decryptedMessage?.attachments ||
    [];

  return (
    <main className="message-view">
      <button
        type="button"
        className="back-button"
        onClick={onBack}
      >
        Back to inbox
      </button>

      <div className="message-header">
        <div className="message-eyebrow">
          {encryptedEnvelope
            ? "END-TO-END ENCRYPTED MESSAGE"
            : "MESSAGE"}
        </div>

        <h2>
          {displaySubject}
        </h2>

        <div className="message-meta">
          <div>
            <strong>
              From
            </strong>

            <span>
              {message?.sender ||
                "Unknown"}
            </span>
          </div>

          <div>
            <strong>
              To
            </strong>

            <span>
              {message?.recipients
                ?.length
                ? message.recipients.join(
                    ", "
                  )
                : "Unknown"}
            </span>
          </div>

          <div>
            <strong>
              Received
            </strong>

            <span>
              {message?.received_at
                ? formatDate(
                    message.received_at
                  )
                : "Unknown"}
            </span>
          </div>
        </div>
      </div>

      {encryptedEnvelope && (
        <section
          className="security-panel"
          style={{
            marginBottom: "14px",
          }}
        >
          <div className="message-eyebrow">
            SECUREMAILSCOPE E2E
          </div>

          <h3>
            {decryptedMessage
              ? "Message decrypted locally"
              : decryptError
                ? "Encrypted message not decrypted"
                : "Decrypting message locally..."}
          </h3>

          <p>
            {decryptedMessage
              ? "The message was received as an encrypted envelope. Its content was decrypted in this browser using the locally held recipient private key."
              : "The message was received as an encrypted envelope. It can only be decrypted with the recipient private key held in this browser."}
          </p>

          <div className="security-findings">
            <div className="security-row">
              <span>
                Content encryption
              </span>

              <span className="positive">
                AES-256-GCM
              </span>
            </div>

            <div className="security-row">
              <span>
                Key encryption
              </span>

              <span className="positive">
                RSA-OAEP-256
              </span>
            </div>

            <div className="security-row">
              <span>
                Recipient key ID
              </span>

              <span className="neutral">
                {encryptedEnvelope.recipient_key_id}
              </span>
            </div>

            <div className="security-row">
              <span>
                Key fingerprint
              </span>

              <span
                className="neutral"
                style={{
                  wordBreak: "break-all",
                  textAlign: "right",
                }}
              >
                {
                  encryptedEnvelope
                    .recipient_key_fingerprint ||
                  "Unavailable"
                }
              </span>
            </div>
          </div>
        </section>
      )}

      {decrypting && (
        <div className="unknown-box">
          <strong>
            Decrypting message locally...
          </strong>

          <p>
            SecureMailScope is using the
            recipient private key stored in
            this browser.
          </p>
        </div>
      )}

      {decryptError && (
        <div className="error-box">
          <strong>
            Unable to decrypt message
          </strong>

          <p>
            {decryptError}
          </p>

          <p>
            Use the End-to-end identity
            panel above to import the
            matching identity backup or to
            publish this browser's key for
            future messages.
          </p>
        </div>
      )}

      {!decrypting &&
        !decryptError &&
        encryptedEnvelope &&
        decryptedMessage && (
          <div className="message-body">
            {displayBody}
          </div>
        )}

      {!encryptedEnvelope && (
        <div className="message-body">
          {displayBody}
        </div>
      )}

      {decryptedAttachments.length >
        0 && (
        <section className="security-panel">
          <div className="message-eyebrow">
            DECRYPTED ATTACHMENTS
          </div>

          <h3>
            {decryptedAttachments.length} file
            {decryptedAttachments.length ===
            1
              ? ""
              : "s"} available
          </h3>

          {decryptedAttachments.map(
            (attachment, index) => (
              <div
                className="security-row"
                key={`${attachment.filename}-${index}`}
              >
                <span>
                  {attachment.filename}
                </span>

                <span className="positive">
                  Decrypted
                </span>
              </div>
            )
          )}

          <p className="security-source">
            Attachment content was included
            inside the encrypted message
            envelope and decrypted locally.
          </p>
        </section>
      )}

      {message?.attachments?.length >
        0 &&
        !encryptedEnvelope && (
        <section className="security-panel">
          <div className="message-eyebrow">
            ATTACHMENTS
          </div>

          <h3>
            {message.attachments.length} file
            {message.attachments.length ===
            1
              ? ""
              : "s"} attached
          </h3>

          {message.attachments.map(
            (attachment, index) => (
              <div
                className="security-row"
                key={`${attachment.filename || attachment.name || "attachment"}-${index}`}
              >
                <span>
                  {
                    attachment.filename ||
                    attachment.name ||
                    `Attachment ${index + 1}`
                  }
                </span>

                <span className="neutral">
                  Attachment
                </span>
              </div>
            )
          )}
        </section>
      )}

      {security && (
        <section className="security-panel">
          <div className="message-eyebrow">
            SECURITY ANALYSIS
          </div>

          <h3>
            Observed message security
          </h3>

          {summary && (
            <p>
              {summary.total_findings ??
                summary.findings
                  ?.length ??
                0}{" "}
              security finding(s) from
              the observed message headers.
            </p>
          )}

          <div className="security-findings">
            <div className="security-row">
              <span>
                Risk
              </span>

              <span className="neutral">
                {risk?.risk_level ||
                  "Unknown"}
              </span>
            </div>

            <div className="security-row">
              <span>
                Authentication
              </span>

              <span className="neutral">
                {[
                  "spf",
                  "dkim",
                  "dmarc",
                ]
                  .map(
                    (method) =>
                      `${method.toUpperCase()} ${
                        authentication
                          ?.summary?.[
                          method
                        ]?.status ||
                        "unobserved"
                      }`
                  )
                  .join(" · ")}
              </span>
            </div>

            <div className="security-row">
              <span>
                HNDL
              </span>

              <span className="neutral">
                {
                  hndl?.status ||
                  hndl?.level ||
                  "Unknown"
                }
              </span>
            </div>
          </div>
        </section>
      )}
    </main>
  );
}

function WorkspaceNav({
  activeView,
  setActiveView,
}) {
  return (
    <nav className="workspace-nav">
      <button
        className={
          activeView ===
          "inbox"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView(
            "inbox"
          )
        }
      >
        Inbox
      </button>

      <button
        className={
          activeView ===
          "sent"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView(
            "sent"
          )
        }
      >
        Sent
      </button>

      <button
        className={
          activeView ===
          "compose"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView(
            "compose"
          )
        }
      >
        Compose
      </button>

      <button
        className={
          activeView ===
          "security"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView(
            "security"
          )
        }
      >
        Security
      </button>

      <button
        className={
          activeView ===
          "forensics"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView(
            "forensics"
          )
        }
      >
        Forensics
      </button>
    </nav>
  );
}

function PlaceholderView({
  eyebrow,
  title,
  description,
}) {
  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">
            {eyebrow}
          </span>

          <h2>
            {title}
          </h2>

          <p>
            {description}
          </p>
        </div>
      </section>

      <section className="placeholder-card">
        <div className="shield">
          ⌁
        </div>

        <h3>
          Workspace ready
        </h3>

        <p>
          This section will connect to
          the SecureMailScope
          intelligence layer as we
          build the next feature.
        </p>
      </section>
    </>
  );
}

function Metric({
  label,
  value,
}) {
  return (
    <div className="metric">
      <span>
        {label}
      </span>

      <strong>
        {value}
      </strong>
    </div>
  );
}

function SecurityRow({
  label,
  value,
  positive = false,
}) {
  return (
    <div className="security-row">
      <span>
        {label}
      </span>

      <span
        className={
          positive
            ? "positive"
            : "neutral"
        }
      >
        {value}
      </span>
    </div>
  );
}

// check-recipient returns mta_sts = { dns, policy: { status, policy:
// { mode, ... } } }. Reading mta_sts.mode always showed "Observed".
function getMtaStsMode(
  assessment
) {
  return (
    assessment?.mta_sts?.policy
      ?.policy?.mode ||
    assessment?.mta_sts?.mode ||
    null
  );
}

function formatMtaStsMode(mode) {
  if (mode === "enforce") {
    return "Enforce";
  }

  if (mode === "testing") {
    return "Testing only";
  }

  if (mode === "none") {
    return "Disabled (none)";
  }

  return "Not published";
}

function normalizeOAuthProvider(
  provider
) {
  const value =
    String(
      provider || ""
    )
      .trim()
      .toLowerCase();

  if (
    value === "gmail" ||
    value === "google"
  ) {
    return "google";
  }

  if (
    value === "microsoft" ||
    value === "outlook" ||
    value === "office365"
  ) {
    return "microsoft";
  }

  return value;
}

function formatProviderName(
  provider
) {
  const normalized =
    normalizeOAuthProvider(
      provider
    );

  if (
    normalized ===
    "google"
  ) {
    return "Google";
  }

  if (
    normalized ===
    "microsoft"
  ) {
    return "Microsoft";
  }

  if (
    normalized ===
    "custom"
  ) {
    return "Custom SMTP";
  }

  if (!normalized) {
    return "Mail provider";
  }

  return normalized
    .replaceAll(
      "_",
      " "
    )
    .replace(
      /\b\w/g,
      (letter) =>
        letter.toUpperCase()
    );
}

function formatAuthenticationLabel(
  account
) {
  if (!account) {
    return "Unknown";
  }

  const authentication =
    account.authentication;

  if (
    authentication ===
    "oauth"
  ) {
    return "OAuth";
  }

  if (
    authentication ===
    "credential"
  ) {
    return "SMTP credential";
  }

  if (
    account.connection_type ===
    "oauth"
  ) {
    return "OAuth";
  }

  if (
    account.connection_type ===
    "smtp"
  ) {
    return "SMTP credential";
  }

  return "Configured";
}

function formatDecision(
  value
) {
  if (!value) {
    return "Unknown";
  }

  return value
    .replaceAll(
      "_",
      " "
    )
    .replace(
      /\b\w/g,
      (letter) =>
        letter.toUpperCase()
    );
}

function formatDate(
  value
) {
  if (!value) {
    return "Unknown";
  }

  // Provider timestamps may arrive as epoch milliseconds.
  const date =
    /^\d+$/.test(String(value))
      ? new Date(Number(value))
      : new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return value;
  }

  return date.toLocaleString(
    [],
    {
      dateStyle:
        "medium",
      timeStyle:
        "short",
    }
  );
}

function formatFileSize(
  bytes
) {
  if (
    !Number.isFinite(
      bytes
    ) ||
    bytes < 0
  ) {
    return "0 B";
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (
    bytes <
    1024 * 1024
  ) {
    return `${(
      bytes / 1024
    ).toFixed(1)} KB`;
  }

  return `${(
    bytes /
    (1024 * 1024)
  ).toFixed(2)} MB`;
}

export default App;