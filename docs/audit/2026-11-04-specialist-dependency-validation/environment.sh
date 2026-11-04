#!/usr/bin/env bash
# Test processes only; dependencies extracted under /tmp.
export CROWDSEC_TEST_RELEASE=/tmp/crowdbastion-specialist-deps/crowdsec-v1.8.1
export CROWDBASTION_TEST_NGINX=/tmp/crowdbastion-specialist-deps/nginx-root/usr/sbin/nginx
export CROWDBASTION_TEST_LUA_PREFIX=/tmp/crowdbastion-specialist-deps/nginx-root
export GOST_TEST_BINARY=/tmp/crowdbastion-specialist-deps/gost/gost
export PATH=/projects/script/CrowdBastion/.venv/bin:"$PATH"
