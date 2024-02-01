#! /bin/sh

if [ -n $1 ]; then
echo $1
    ZITADEL_IMPORT=$1/zitadel
else
    echo "need message import"
    exit 3
fi

protoc \
    -I=/proto/include \
    --go_opt=paths=source_relative \
    --go_out /go/src/github.com/zitadel/zitadel/pkg/grpc \
    /proto/include/authoption/options.proto

protoc \
    -I=/proto/include \
    --go_opt=module=$PREFIX \
    --go-grpc_opt=module=$PREFIX \
    --go_opt=Mzitadel/admin.proto=${ZITADEL_IMPORT}/admin \
    --go_opt=Mzitadel/app.proto=${ZITADEL_IMPORT}/app \
    --go_opt=Mzitadel/auth.proto=${ZITADEL_IMPORT}/auth \
    --go_opt=Mzitadel/action.proto=${ZITADEL_IMPORT}/action \
    --go_opt=Mzitadel/auth_n_key.proto=${ZITADEL_IMPORT}/authn \
    --go_opt=Mzitadel/change.proto=${ZITADEL_IMPORT}/change \
    --go_opt=Mzitadel/event.proto=${ZITADEL_IMPORT}/event \
    --go_opt=Mzitadel/feature.proto=${ZITADEL_IMPORT}/feature \
    --go_opt=Mzitadel/idp.proto=${ZITADEL_IMPORT}/idp \
    --go_opt=Mzitadel/instance.proto=${ZITADEL_IMPORT}/instance \
    --go_opt=Mzitadel/management.proto=${ZITADEL_IMPORT}/management \
    --go_opt=Mzitadel/member.proto=${ZITADEL_IMPORT}/member \
    --go_opt=Mzitadel/message.proto=${ZITADEL_IMPORT}/message \
    --go_opt=Mzitadel/metadata.proto=${ZITADEL_IMPORT}/metadata \
    --go_opt=Mzitadel/milestone/v1/milestone.proto=${ZITADEL_IMPORT}/milestone \
    --go_opt=Mzitadel/object.proto=${ZITADEL_IMPORT}/object \
    --go_opt=Mzitadel/options.proto=${ZITADEL_IMPORT}/authoption \
    --go_opt=Mzitadel/org.proto=${ZITADEL_IMPORT}/org \
    --go_opt=Mzitadel/policy.proto=${ZITADEL_IMPORT}/policy \
    --go_opt=Mzitadel/project.proto=${ZITADEL_IMPORT}/project \
    --go_opt=Mzitadel/quota.proto=${ZITADEL_IMPORT}/quota \
    --go_opt=Mzitadel/settings.proto=${ZITADEL_IMPORT}/settings \
    --go_opt=Mzitadel/system.proto=${ZITADEL_IMPORT}/system \
    --go_opt=Mzitadel/text.proto=${ZITADEL_IMPORT}/text \
    --go_opt=Mzitadel/user.proto=${ZITADEL_IMPORT}/user \
    --go_opt=Mzitadel/v1.proto=${ZITADEL_IMPORT}/v1 \
    --go_opt=Mzitadel/protoc_gen_zitadel/v2/options.proto=${ZITADEL_IMPORT}/protoc/v2 \
    --go_opt=Mzitadel/object/v2beta/object.proto=${ZITADEL_IMPORT}/object/v2beta \
    --go_opt=Mzitadel/session/v2beta/challenge.proto=${ZITADEL_IMPORT}/session/v2beta \
    --go_opt=Mzitadel/session/v2beta/session.proto=${ZITADEL_IMPORT}/session/v2beta \
    --go_opt=Mzitadel/session/v2beta/session_service.proto=${ZITADEL_IMPORT}/session/v2beta \
    --go_opt=Mzitadel/oidc/v2beta/authorization.proto=${ZITADEL_IMPORT}/oidc/v2beta \
    --go_opt=Mzitadel/oidc/v2beta/oidc_service.proto=${ZITADEL_IMPORT}/oidc/v2beta \
    --go_opt=Mzitadel/org/v2beta/org_service.proto=${ZITADEL_IMPORT}/org/v2beta \
    --go_opt=Mzitadel/settings/v2beta/branding_settings.proto=${ZITADEL_IMPORT}/settings/v2beta \
    --go_opt=Mzitadel/settings/v2beta/domain_settings.proto=${ZITADEL_IMPORT}/settings/v2beta \
    --go_opt=Mzitadel/settings/v2beta/legal_settings.proto=${ZITADEL_IMPORT}/settings/v2beta \
    --go_opt=Mzitadel/settings/v2beta/lockout_settings.proto=${ZITADEL_IMPORT}/settings/v2beta \
    --go_opt=Mzitadel/settings/v2beta/login_settings.proto=${ZITADEL_IMPORT}/settings/v2beta \
    --go_opt=Mzitadel/settings/v2beta/password_settings.proto=${ZITADEL_IMPORT}/settings/v2beta \
    --go_opt=Mzitadel/settings/v2beta/settings.proto=${ZITADEL_IMPORT}/settings/v2beta \
    --go_opt=Mzitadel/settings/v2beta/settings_service.proto=${ZITADEL_IMPORT}/settings/v2beta \
    --go_opt=Mzitadel/user/v2beta/auth.proto=${ZITADEL_IMPORT}/user/v2beta \
    --go_opt=Mzitadel/user/v2beta/email.proto=${ZITADEL_IMPORT}/user/v2beta \
    --go_opt=Mzitadel/user/v2beta/idp.proto=${ZITADEL_IMPORT}/user/v2beta \
    --go_opt=Mzitadel/user/v2beta/password.proto=${ZITADEL_IMPORT}/user/v2beta \
    --go_opt=Mzitadel/user/v2beta/phone.proto=${ZITADEL_IMPORT}/user/v2beta \
    --go_opt=Mzitadel/user/v2beta/query.proto=${ZITADEL_IMPORT}/user/v2beta \
    --go_opt=Mzitadel/user/v2beta/user.proto=${ZITADEL_IMPORT}/user/v2beta \
    --go_opt=Mzitadel/user/v2beta/user_service.proto=${ZITADEL_IMPORT}/user/v2beta \
    --go_out /go/src \
    --go-grpc_out /go/src \
    $(find /proto/include/zitadel -iname *.proto)
