use std::sync::Arc;
use std::time::Duration;

use mqtt_proto::v5::*;
use mqtt_proto::*;
use tokio::time::sleep;
use ConnectReasonCode::*;

use crate::config::Config;
use crate::tests::utils::MockConn;

use super::assert_connack;

#[tokio::test]
async fn test_sub_unsub_simple() {
    let (conn, mut control) = MockConn::new(3333, Config::new_allow_anonymous());
    let task = control.start(conn);

    let connect = Connect::new(Arc::new("client identifier".to_owned()), 10);
    let connack = Connack::new(false, Success);
    control.write_packet_v5(connect.into()).await;
    let packet = control.read_packet_v5().await;
    assert_connack!(packet, connack);

    let sub_pk_id = Pid::try_from(23).unwrap();
    let subscribe = Subscribe::new(
        sub_pk_id,
        vec![
            (
                TopicFilter::try_from("abc/0".to_owned()).unwrap(),
                SubscriptionOptions::new(QoS::Level0),
            ),
            (
                TopicFilter::try_from("xyz/1".to_owned()).unwrap(),
                SubscriptionOptions::new(QoS::Level1),
            ),
            (
                TopicFilter::try_from("ijk/2".to_owned()).unwrap(),
                SubscriptionOptions::new(QoS::Level2),
            ),
        ],
    );
    let suback = Suback::new(
        sub_pk_id,
        vec![
            SubscribeReasonCode::GrantedQoS0,
            SubscribeReasonCode::GrantedQoS1,
            SubscribeReasonCode::GrantedQoS2,
        ],
    );
    control.write_packet_v5(subscribe.into()).await;
    let packet = control.read_packet_v5().await;
    let expected_packet = Packet::Suback(suback);
    assert_eq!(packet, expected_packet);

    let unsub_pk_id = Pid::try_from(24).unwrap();
    let unsubscribe = Unsubscribe::new(
        unsub_pk_id,
        vec![
            TopicFilter::try_from("abc/0".to_owned()).unwrap(),
            TopicFilter::try_from("xxx/+".to_owned()).unwrap(),
        ],
    );
    control.write_packet_v5(unsubscribe.into()).await;
    let packet = control.read_packet_v5().await;
    let expected_packet = Unsuback::new(
        unsub_pk_id,
        vec![
            UnsubscribeReasonCode::Success,
            UnsubscribeReasonCode::NoSubscriptionExisted,
        ],
    )
    .into();
    assert_eq!(packet, expected_packet);

    sleep(Duration::from_millis(10)).await;
    assert!(!task.is_finished());
}

#[tokio::test]
async fn test_subscribe_reject_empty_topics() {
    let (conn, mut control) = MockConn::new(3333, Config::new_allow_anonymous());
    let task = control.start(conn);

    let connect = Connect::new(Arc::new("client identifier".to_owned()), 10);
    let connack = Connack::new(false, Success);
    control.write_packet_v5(connect.into()).await;
    let packet = control.read_packet_v5().await;
    assert_connack!(packet, connack);

    let sub_pk_id = Pid::try_from(23).unwrap();
    let subscribe = Subscribe::new(sub_pk_id, vec![]);
    control.write_packet_v5(subscribe.into()).await;

    sleep(Duration::from_millis(10)).await;
    assert!(control.try_read_packet_v5().is_err());
    assert!(task.is_finished());
}
