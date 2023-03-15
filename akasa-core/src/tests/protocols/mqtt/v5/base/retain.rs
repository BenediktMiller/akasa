use std::sync::Arc;
use std::time::Duration;

use mqtt_proto::v5::*;
use mqtt_proto::*;
use tokio::time::sleep;

use crate::config::Config;
use crate::state::GlobalState;
use crate::tests::utils::MockConn;

use super::super::ClientV5;

#[tokio::test]
async fn test_retain_simple() {
    let (task, mut client) = MockConn::start(3333, Config::new_allow_anonymous());

    client.connect("client id", true, false).await;
    client
        .send_publish(QoS::Level1, 22, "xyz/1", vec![3, 5, 55], |p| {
            p.retain = true
        })
        .await;
    client
        .recv_puback(22, PubackReasonCode::NoMatchingSubscribers)
        .await;

    let sub_topics = vec![
        ("abc/0", SubscriptionOptions::new(QoS::Level0)),
        ("xyz/1", SubscriptionOptions::new(QoS::Level1)),
    ];
    client.send_subscribe(23, sub_topics).await;
    client
        .recv_publish(QoS::Level1, 1, "xyz/1", vec![3, 5, 55], |p| p.retain = true)
        .await;
    let sub_codes = vec![
        SubscribeReasonCode::GrantedQoS0,
        SubscribeReasonCode::GrantedQoS1,
    ];
    client.recv_suback(23, sub_codes).await;

    sleep(Duration::from_millis(10)).await;
    assert!(!task.is_finished());
}

#[tokio::test]
async fn test_retain_different_clients() {
    let global = Arc::new(GlobalState::new(
        "127.0.0.1:1883".parse().unwrap(),
        Config::new_allow_anonymous(),
    ));
    let (task1, mut client1) = MockConn::start_with_global(111, Arc::clone(&global));
    let (task2, mut client2) = MockConn::start_with_global(222, global);

    // client 1: publish retain message
    {
        client1.connect("client id 1", true, false).await;
        client1
            .send_publish(QoS::Level1, 11, "xyz/1", vec![3, 5, 55], |p| {
                p.retain = true
            })
            .await;
        client1
            .recv_puback(11, PubackReasonCode::NoMatchingSubscribers)
            .await;
    }

    // client 2: subscribe and received a retain message
    {
        client2.connect("client id 2", true, false).await;

        // subscribe multiple times
        for (sub_pid, pub_pid) in [(22, 1), (23, 2)] {
            let sub_topics = vec![
                ("abc/0", SubscriptionOptions::new(QoS::Level0)),
                ("xyz/1", SubscriptionOptions::new(QoS::Level1)),
            ];
            client2.send_subscribe(sub_pid, sub_topics).await;
            client2
                .recv_publish(QoS::Level1, pub_pid, "xyz/1", vec![3, 5, 55], |p| {
                    p.retain = true
                })
                .await;
            let sub_codes = vec![
                SubscribeReasonCode::GrantedQoS0,
                SubscribeReasonCode::GrantedQoS1,
            ];
            client2.recv_suback(sub_pid, sub_codes).await;
        }
    }

    sleep(Duration::from_millis(10)).await;
    assert!(!task1.is_finished());
    assert!(!task2.is_finished());
}
